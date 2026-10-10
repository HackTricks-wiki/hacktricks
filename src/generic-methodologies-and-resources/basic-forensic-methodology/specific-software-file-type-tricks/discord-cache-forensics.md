# Форензика кешу Discord (Chromium Disk Cache)

{{#include ../../../banners/hacktricks-training.md}}

На цій сторінці описано, як проводити первинний аналіз артефактів кешу Discord Desktop, щоб знайти локально кешовані медіафайли, адреси webhook і дані для кореляції активності. Настільний клієнт Discord використовує Electron, а Electron зберігає дані сеансу, зокрема дисковий кеш, у `sessionData`.<sup>[[3]](#references)[[4]](#references)</sup>

## Де шукати (Windows/macOS/Linux)

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

Це стандартні шляхи, які використовує згаданий парсер; Electron дозволяє застосунку перевизначити `sessionData`, тому під час отримання даних перевірте фактичний шлях до профілю.<sup>[[2]](#references)[[4]](#references)</sup>

Структура `index` + `data_#` + `f_######` відповідає дисковому кешу Chromium з бекендом blockfile; не позначайте його як Simple Cache, не перевіривши бекенд, оскільки Chromium документує окремі реалізації кешу.<sup>[[5]](#references)</sup>

Основні структури на диску в `Cache_Data`:
- `index`: індекс кешу Blockfile, який використовується для пошуку записів.
- `data_#`: файли фіксованого розміру, що можуть містити метадані кешу, HTTP-заголовки та дані відповіді.
- `f_######`: окремі файли для даних, розмір яких перевищує обмеження block-файлів; ці файли містять збережені дані без заголовків block-файлів.

Видалення повідомлень, каналів або серверів не гарантує видалення байтів, уже кешованих локально, але Chromium може будь-коли видалити або створити заново файли кешу. Розглядайте вцілілі артефакти як випадкові докази, а час модифікації файлів використовуйте лише як приблизний сигнал локального запису, який потрібно зіставити з іншими телеметричними даними.<sup>[[5]](#references)[[6]](#references)</sup>

## Що можна відновити

Залежно від того, що було завантажено й ще не видалено з кешу, під час первинного аналізу можна відновити кешовані вкладення, медіафайли, URL-адреси та хеші файлів; сам кеш не доводить, що елемент було викрадено.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Вкладення та мініатюри, на які посилаються URL-адреси CDN Discord.
- Зображення, GIF-файли й відео (наприклад, `.jpg`, `.png`, `.gif`, `.webp`, `.mp4` і `.webm`).
- URL-адреси webhook, як-от `https://discord.com/api/webhooks/...`.<sup>[[2]](#references)[[7]](#references)</sup>
- Виклики API Discord, як-от `https://discord.com/api/vX/...`.<sup>[[2]](#references)</sup>
- SHA-256-хеші відновлених медіафайлів для порівняння з відомими наборами даних або розвідувальними потоками.<sup>[[1]](#references)[[2]](#references)</sup>

## Швидкий первинний аналіз (вручну)

- Виконайте пошук у кеші за артефактами з високою інформативністю. Ці шаблони відповідають виразам URL-адрес, які використовує згаданий парсер, і є фільтрами для первинного аналізу, а не вичерпним переліком індикаторів.<sup>[[2]](#references)</sup>
  - Адреси webhook:
    - Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
    - Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
  - URL-адреси вкладень/CDN:
    - strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
  - Виклики API Discord:
    - strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Відсортуйте записи кешу за часом модифікації, щоб скласти приблизну послідовність; mtime є сигналом файлової системи й сам по собі не встановлює, коли об’єкт Discord було завантажено чи надіслано.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
  - Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Аналіз записів f_* (тіло HTTP + заголовки)

У структурі blockfile файли `f_######` є окремими потоками даних і не обов’язково починаються з повної HTTP-відповіді. Якщо отриманий файл містить серіалізовані HTTP-заголовки, за якими йде `\r\n\r\n`, розділіть його за першим таким роздільником і перевірте:<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type: щоб визначити тип медіафайлу
- Content-Location або X-Original-URL: початкову віддалену URL-адресу для попереднього перегляду/кореляції
- Content-Encoding: може бути gzip/deflate/br (Brotli).

Після цього медіафайли можна витягти, відокремивши заголовки від тіла й, за потреби, розпакувавши їх відповідно до `Content-Encoding`; згаданий парсер підтримує Brotli, gzip і deflate. Визначення типу за магічними байтами стане в пригоді, якщо `Content-Type` відсутній, але це лише евристика.<sup>[[2]](#references)</sup>

## Автоматизований DFIR: Discord Forensic Suite (CLI/GUI)

- Репозиторій: [Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser).<sup>[[1]](#references)</sup>
- Функція: рекурсивно сканує папку кешу Discord, знаходить URL-адреси webhook/API/вкладень, аналізує тіла `f_*`, за потреби вирізає медіафайли й формує HTML- та CSV-звіти, а також, за бажанням, хронологічну шкалу з SHA-256-хешами.<sup>[[1]](#references)[[2]](#references)</sup>

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

The CLI визначає такі параметри та назви вихідних файлів:<sup>[[2]](#references)</sup>
- --cache: Шлях до каталогу Discord Cache_Data
- --format html|csv|both
- --timeline: Створює впорядковану часову шкалу у форматі CSV (за часом зміни)
- --extra: Також сканує сусідні каталоги Code Cache і GPUCache
- --carve: Вилучає медіафайли з необроблених байтів кешу за розпізнаними сигнатурами медіафайлів (зображення/відео)
- Вивід: `<output>.html`, `<output>.csv`, необов’язковий `<output>_timeline.csv` і каталог `<output>_media` з витягнутими або вилученими файлами.

## Поради аналітикам

- Зіставляйте час зміни (mtime) файлів `f_*` і `data_*` з періодами активності користувачів або зловмисників та незалежною телеметрією; mtime не є точним часом події.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Обчислюйте хеші відновлених медіафайлів (SHA-256) і порівнюйте їх із відомими шкідливими даними або наборами даних ексфільтрації.<sup>[[1]](#references)[[2]](#references)</sup>
- Вважайте витягнуті URL-адреси webhook обліковими даними. Не викликайте їх лише для перевірки доступності; зберігайте їх у безпечному місці, узгодьте відкликання або ротацію та використовуйте пов’язану мережеву телеметрію для ретроспективного пошуку.<sup>[[7]](#references)</sup>
- Видалення на сервері не гарантує знищення локально кешованих байтів. Якщо є можливість отримати дані, скопіюйте весь каталог `Cache` і пов’язані сусідні кеші (`Code Cache`, `GPUCache`) до їх очищення або повторного створення кешу.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Набір інструментів для комп’ютерної криміналістики Discord (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [2] [CLI набору інструментів для комп’ютерної криміналістики Discord](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [Як Discord непомітно оновив мільйони користувачів до 64-бітної архітектури](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [app | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [Дисковий кеш](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [Discord як C2 і кешовані докази, що залишилися після нього](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Discord Webhooks – виконання webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
