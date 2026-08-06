# Форензика кешу Discord (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

Ця сторінка узагальнює, як виконувати тріаж артефактів кешу Discord Desktop для відновлення ексфільтрованих файлів, webhook endpoints і часових шкал активності. Discord Desktop є Electron/Chromium app і використовує Chromium Simple Cache на диску.

## Де шукати (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Ключові структури на диску всередині Cache_Data:<sup>[[1]](#references)</sup>
- index: база даних індексу Simple Cache
- data_#: бінарні файли блоків кешу, які можуть містити кілька кешованих об'єктів
- f_######: окремі кешовані записи, що зберігаються як standalone-файли (часто з більшими body)

Примітка: видалення повідомлень/каналів/серверів у Discord не очищає цей локальний кеш. Кешовані елементи часто залишаються, а їхні часові мітки узгоджуються з активністю користувача, що дає змогу відновити часову шкалу.<sup>[[1]](#references)</sup>

## Що можна відновити

- Ексфільтровані attachments і thumbnails, отримані через cdn.discordapp.com/media.discordapp.net
- Images, GIFs, videos (наприклад, .jpg, .png, .gif, .webp, .mp4, .webm)
- Webhook URLs (https://discord.com/api/webhooks/…)<sup>[[3]](#references)</sup>
- Discord API calls (https://discord.com/api/vX/…)
- Корисно для кореляції beaconing/активності ексфільтрації та хешування media для intel matching<sup>[[1]](#references)</sup>

## Швидкий тріаж (вручну)

- Виконайте grep кешу для артефактів із високою сигнальністю:
- Webhook endpoints:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URLs:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Discord API calls:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Відсортуйте кешовані записи за часом зміни, щоб швидко побудувати часову шкалу (mtime відображає момент потрапляння об'єкта в кеш):
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Парсинг записів f_* (HTTP body + headers)

Файли, що починаються з f_, містять HTTP response headers, за якими йде body. Блок заголовків зазвичай закінчується на \r\n\r\n. Корисні response headers включають:
- Content-Type: для визначення типу media
- Content-Location або X-Original-URL: оригінальний remote URL для preview/кореляції
- Content-Encoding: може бути gzip/deflate/br (Brotli)

Media можна витягти, відокремивши headers від body і, за потреби, виконавши decompressing на основі Content-Encoding. Визначення за magic bytes корисне, коли Content-Type відсутній.

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser<sup>[[2]](#references)</sup>
- Function: рекурсивно сканує папку кешу Discord, знаходить webhook/API/attachment URLs, парсить body файлів f_*, за потреби виконує carving media та створює HTML + CSV звіти часової шкали з SHA‑256 hashes.<sup>[[2]](#references)</sup>

Приклад використання CLI:
```bash
# Acquire cache (copy directory for offline parsing), then run:
python3 discord_forensic_suite_cli \
--cache "%AppData%\discord\Cache\Cache_Data" \
--outdir C:\IR\discord-cache \
--output discord_cache_report \
--format both \
--timeline \
--extra \
--carve \
--verbose
```
Ключові параметри:
- --cache: шлях до Cache_Data
- --format html|csv|both
- --timeline: створити впорядковану CSV-часову шкалу (за часом модифікації)
- --extra: також сканувати сусідні Cache Code та GPUCache
- --carve: витягувати медіафайли із сирих байтів поблизу збігів regex (зображення/відео)
- Вивід: HTML-звіт, CSV-звіт, CSV-часова шкала та папка media із витягнутими/відновленими файлами

## Поради аналітику

- Зіставляйте час модифікації (mtime) файлів f_* і data_* з періодами активності користувача/зловмисника, щоб відновити часову шкалу.
- Хешуйте відновлені медіафайли (SHA-256) і порівнюйте їх із відомими шкідливими наборами даних або наборами даних ексфільтрації.
- Витягнуті URL webhook можна перевірити на доступність або ротувати; розгляньте можливість додавання їх до блок-листів і ретроспективного пошуку в проксі.
- Cache зберігається після «очищення» на стороні сервера. Якщо отримання можливе, зберіть увесь каталог Cache і пов’язані сусідні кеші (Code Cache, GPUCache).<sup>[[1]](#references)</sup>

## Посилання

- [1] [Discord як C2 і кешовані докази, що залишаються після нього](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [2] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [3] [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
