# Форензика кешу Discord (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

Ця сторінка підсумовує, як проводити триаж артефактів кешу Discord Desktop для відновлення файлів, виведених назовні, webhook-ендпойнтів та хронології активності. Discord Desktop — це Electron/Chromium-додаток і використовує Chromium Simple Cache на диску.

## Де шукати (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Ключові структури на диску всередині Cache_Data:
- index: Simple Cache index database
- data_#: Binary cache block files that can contain multiple cached objects
- f_######: Individual cached entries stored as standalone files (often larger bodies)

Примітка: Видалення повідомлень/каналів/серверів у Discord не очищує цей локальний кеш. Закешовані елементи часто залишаються, а часові мітки файлів відповідають активності користувача, що дозволяє відновлювати хронологію.

## Що можна відновити

- Виведені вкладення та мініатюри, отримані через cdn.discordapp.com/media.discordapp.net
- Зображення, GIF, відео (наприклад, .jpg, .png, .gif, .webp, .mp4, .webm)
- Webhook URLs (https://discord.com/api/webhooks/…)
- Discord API виклики (https://discord.com/api/vX/…)
- Корисно для кореляції beaconing/exfil активності та хешування медіафайлів для зіставлення intel

## Швидка триажа (ручна)

- Шукати в кеші високосигнальні артефакти:
- Webhook endpoints:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URLs:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Discord API calls:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Сортуйте кешовані записи за часом модифікації, щоб швидко побудувати хронологію (mtime відображає момент, коли об'єкт потрапив у кеш):
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## Парсинг f_* записів (HTTP body + headers)

Файли, що починаються з f_, містять HTTP response headers, після яких йде тіло. Блок заголовків зазвичай закінчується \r\n\r\n. Корисні заголовки відповіді включають:
- Content-Type: To infer media type
- Content-Location or X-Original-URL: Original remote URL for preview/correlation
- Content-Encoding: May be gzip/deflate/br (Brotli)

Медіа можна витягти, відокремивши заголовки від тіла та за потреби розпакувавши згідно з Content-Encoding. Magic-byte sniffing корисний, коли Content-Type відсутній.

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser
- Function: Recursively scans Discord’s cache folder, finds webhook/API/attachment URLs, parses f_* bodies, optionally carves media, and outputs HTML + CSV timeline reports with SHA‑256 hashes.

Example CLI usage:
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
Key options:
- --cache: Path to Cache_Data
- --format html|csv|both
- --timeline: Створити впорядковану CSV-таймлайн (за часом модифікації)
- --extra: Також сканувати суміжні Code Cache і GPUCache
- --carve: Вирізати медіа з сирих байтів поблизу збігів regex (images/video)
- Output: HTML report, CSV report, CSV timeline, and a media folder with carved/extracted files

## Поради аналітику

- Корелюйте час модифікації (mtime) файлів f_* і data_* з вікнами активності користувача/атакувальника, щоб реконструювати таймлайн.
- Хешуйте відновлені медіа (SHA-256) і порівнюйте з відомими шкідливими або exfil наборами даних.
- Вилучені webhook URL можна перевірити на працездатність або змінити (rotate); розгляньте додавання їх до blocklists і ретро-хантинг проксі.
- Cache зберігається навіть після «витирання» на боці сервера. Якщо можлива аквізиція, зберіть весь каталог Cache та суміжні кеші (Code Cache, GPUCache).

## References

- [Discord as a C2 and the cached evidence left behind](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
