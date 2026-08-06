# Discord Cache Forensics (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

Bu sayfa, exfiltrate edilmiş dosyaları, webhook endpoint'lerini ve etkinlik zaman çizelgelerini kurtarmak için Discord Desktop cache artifact'larının nasıl triage edileceğini özetler. Discord Desktop bir Electron/Chromium uygulamasıdır ve diskte Chromium Simple Cache kullanır.

## Nereye bakılmalı (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Cache_Data içindeki önemli disk yapıları:<sup>[[1]](#references)</sup>
- index: Simple Cache index database
- data_#: Birden fazla cached object içerebilen binary cache block dosyaları
- f_######: Standalone dosyalar olarak saklanan tekil cached entry'ler (genellikle daha büyük body'ler)

Not: Discord'da mesajları/channels/servers silmek bu local cache'i temizlemez. Cached item'lar genellikle kalmaya devam eder ve dosya timestamp'leri kullanıcı etkinliğiyle örtüşür; bu da zaman çizelgesi oluşturmayı mümkün kılar.<sup>[[1]](#references)</sup>

## Neler kurtarılabilir

- cdn.discordapp.com/media.discordapp.net üzerinden alınan exfiltrate edilmiş attachment'lar ve thumbnail'ler
- Görseller, GIF'ler, videolar (ör. .jpg, .png, .gif, .webp, .mp4, .webm)
- Webhook URL'leri (https://discord.com/api/webhooks/…)<sup>[[3]](#references)</sup>
- Discord API çağrıları (https://discord.com/api/vX/…)
- Beaconing/exfil activity ile korelasyon kurmak ve intel matching için media hash'lemek açısından faydalıdır<sup>[[1]](#references)</sup>

## Hızlı triage (manuel)

- Cache'i yüksek sinyalli artifact'lar için Grep'leyin:
- Webhook endpoint'leri:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URL'leri:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Discord API çağrıları:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Hızlı bir zaman çizelgesi oluşturmak için cached entry'leri değiştirilme zamanına göre sıralayın (mtime, object'in cache'e ne zaman girdiğini gösterir):
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## f_* entry'lerini parse etme (HTTP body + headers)

f_ ile başlayan dosyalar, HTTP response headers'ı ve ardından body'yi içerir. Header block genellikle \r\n\r\n ile sona erer. Faydalı response header'ları şunlardır:
- Content-Type: Media type'ı tahmin etmek için
- Content-Location veya X-Original-URL: Preview/correlation için original remote URL
- Content-Encoding: gzip/deflate/br (Brotli) olabilir

Media, header'lar body'den ayrılarak ve isteğe bağlı olarak Content-Encoding'e göre decompress edilerek extract edilebilir. Content-Type mevcut olmadığında magic-byte sniffing faydalıdır.

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser<sup>[[2]](#references)</sup>
- Function: Discord'un cache folder'ını recursive olarak tarar, webhook/API/attachment URL'lerini bulur, f_* body'lerini parse eder, isteğe bağlı olarak media carve eder ve SHA‑256 hash'leriyle HTML + CSV timeline report'ları oluşturur.<sup>[[2]](#references)</sup>

Example CLI kullanımı:
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
Ana seçenekler:
- --cache: Cache_Data yolu
- --format html|csv|both
- --timeline: Sıralı CSV zaman çizelgesi oluşturur (modified time'a göre)
- --extra: Kardeş Code Cache ve GPUCache dizinlerini de tarar
- --carve: Regex eşleşmelerinin yakınındaki ham byte'lardan medyayı (görseller/video) carve eder
- Çıktı: HTML raporu, CSV raporu, CSV zaman çizelgesi ve carve/extract edilen dosyaların bulunduğu bir media klasörü

## Analyst ipuçları

- Bir zaman çizelgesi oluşturmak için f_* ve data_* dosyalarının modified time (mtime) değerlerini kullanıcı/attacker etkinlik zaman aralıklarıyla ilişkilendirin.
- Kurtarılan medyanın hash'ini (SHA-256) alın ve known-bad veya exfil dataset'leriyle karşılaştırın.
- Extract edilen webhook URL'leri için liveness testi yapılabilir veya URL'ler rotate edilebilir; bunları blocklist'lere eklemeyi ve proxy'lerde retro-hunting yapmayı değerlendirin.
- Server side'da “wiping” işlemi yapıldıktan sonra cache kalıcı olur. Acquisition mümkünse Cache dizininin tamamını ve ilgili kardeş cache'leri (Code Cache, GPUCache) toplayın.<sup>[[1]](#references)</sup>

## Referanslar

- [1] [Discord bir C2 olarak ve geride bıraktığı cache kanıtları](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [2] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [3] [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
