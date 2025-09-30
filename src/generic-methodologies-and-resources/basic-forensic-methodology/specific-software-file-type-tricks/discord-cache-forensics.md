# Discord Cache Forensics (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

Bu sayfa, Discord Desktop önbellek artifaktlarını triage ederek dışarı aktarılmış dosyaları, webhook uç noktalarını ve aktivite zaman çizelgelerini nasıl kurtarabileceğinizi özetler. Discord Desktop bir Electron/Chromium uygulamasıdır ve disk üzerinde Chromium Simple Cache kullanır.

## Nerelere bakılmalı (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Cache_Data içindeki önemli dosya yapıları:
- index: Simple Cache index database
- data_#: Binary cache block files that can contain multiple cached objects
- f_######: Individual cached entries stored as standalone files (often larger bodies)

Not: Discord içinde mesajları/kanalları/sunucuları silmek bu yerel önbelleği temizlemez. Önbelleğe alınan öğeler genellikle kalır ve dosya zaman damgaları kullanıcı etkinliğiyle hizalanır; bu da zaman çizelgesi yeniden inşasını mümkün kılar.

## Neler kurtarılabilir

- cdn.discordapp.com/media.discordapp.net üzerinden alınan dışarı aktarılmış ekler ve küçük resimler
- Görseller, GIF'ler, videolar (ör. .jpg, .png, .gif, .webp, .mp4, .webm)
- Webhook URL'leri (https://discord.com/api/webhooks/…)
- Discord API çağrıları (https://discord.com/api/vX/…)
- beaconing/exfil etkinliğini ilişkilendirmek ve istihbarat eşleştirmesi için medyayı hashlemek açısından faydalı

## Hızlı triage (manuel)

- Yüksek sinyal taşıyan artifaktlar için önbellekte arama:
- Webhook uç noktaları:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Ek/ CDN URL'leri:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Discord API çağrıları:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Önbelleğe alınan kayıtları değiştirilme zamanına göre sıralayarak hızlı bir zaman çizelgesi oluşturun (mtime nesnenin önbelleğe alındığı zamanı yansıtır):
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## f_* girişlerini ayrıştırma (HTTP gövdesi + başlıklar)

f_ ile başlayan dosyalar HTTP yanıt başlıklarını ve ardından gövdeyi içerir. Başlık bloğu tipik olarak \r\n\r\n ile sona erer. Faydalı yanıt başlıkları şunlardır:
- Content-Type: Medya türünü çıkarsamak için
- Content-Location or X-Original-URL: Önizleme/korelasyon için orijinal uzak URL
- Content-Encoding: gzip/deflate/br (Brotli) olabilir

Medya, başlıkları gövdeden ayırarak ve isteğe bağlı olarak Content-Encoding'e göre açarak çıkarılabilir. Content-Type yoksa magic-byte sniffing faydalıdır.

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
Anahtar seçenekler:
- --cache: Cache_Data dizinine giden yol
- --format html|csv|both
- --timeline: Değiştirilme zamanına (modified time) göre sıralanmış bir CSV timeline üretir
- --extra: Kardeş Code Cache ve GPUCache'i de tara
- --carve: regex eşleşmelerine yakın ham byte'lardan medyayı carve eder (görüntü/video)
- Output: HTML raporu, CSV raporu, CSV timeline ve carved/extracted dosyalar içeren bir medya klasörü

## Analist ipuçları

- f_* ve data_* dosyalarının modified time (mtime) değerlerini kullanıcı/saldırgan etkinlik pencereleriyle korelasyonlayarak bir zaman çizelgesi oluşturun.
- Kurtarılan medyaların hash'ini (SHA-256) alın ve known-bad veya exfil dataset'leriyle karşılaştırın.
- Çıkarılan webhook URL'leri liveness için test edilebilir veya rotated edilebilir; bunları blocklists ve retro-hunting proxy'lerine eklemeyi düşünün.
- Cache, sunucu tarafında “wiping” sonrasında kalıcıdır. Acquisition mümkünse, tüm Cache dizinini ve ilgili kardeş cache'leri (Code Cache, GPUCache) toplayın.

## References

- [Discord as a C2 and the cached evidence left behind](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
