# Discord Cache Forensics (Chromium Simple Cache)

{{#include ../../../banners/hacktricks-training.md}}

Bu sayfa, exfiltrate edilmiş dosyaları, webhook uç noktalarını ve etkinlik zaman çizelgelerini kurtarmak için Discord Desktop cache artifact'larının nasıl triage edileceğini özetler. Discord Desktop bir Electron/Chromium uygulamasıdır ve diskte Chromium Simple Cache kullanır.

## Nereye bakılmalı (Windows/macOS/Linux)

- Windows: %AppData%\discord\Cache\Cache_Data
- macOS: ~/Library/Application Support/discord/Cache/Cache_Data
- Linux: ~/.config/discord/Cache/Cache_Data

Cache_Data içindeki diskte bulunan temel yapılar:<sup>[[1]](#references)</sup>
- index: Simple Cache index database
- data_#: Birden fazla cached object içerebilen binary cache block dosyaları
- f_######: Standalone dosyalar olarak depolanan bireysel cached entry'ler (genellikle daha büyük body'ler)

Not: Discord'da mesajların/kanalların/server'ların silinmesi bu local cache'i temizlemez. Cached item'lar sıklıkla kalmaya devam eder ve dosya timestamp'leri user activity ile eşleşerek timeline reconstruction olanağı sağlar.<sup>[[1]](#references)</sup>

## Neler kurtarılabilir

- cdn.discordapp.com/media.discord.net üzerinden getirilen exfiltrate edilmiş attachment'lar ve thumbnail'ler
- Görseller, GIF'ler, videolar (ör. .jpg, .png, .gif, .webp, .mp4, .webm)
- Webhook URL'leri (https://discord.com/api/webhooks/…)<sup>[[3]](#references)</sup>
- Discord API çağrıları (https://discord.com/api/vX/…)
- Beaconing/exfil activity ile correlation yapmak ve intel matching için media hash'lemek açısından yararlıdır<sup>[[1]](#references)</sup>

## Hızlı triage (manuel)

- Cache'i high-signal artifact'lar için Grep'leyin:
- Webhook uç noktaları:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URL'leri:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discord(app)?\.com/attachments/"
- Discord API çağrıları:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Hızlı bir timeline oluşturmak için cached entry'leri modified time'a göre sıralayın (mtime, object'in cache'e ne zaman girdiğini gösterir):
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## f_* entry'lerini parse etme (HTTP body + headers)

f_ ile başlayan dosyalar, HTTP response headers'ı ve ardından body'yi içerir. Header block genellikle \r\n\r\n ile sonlanır. Yararlı response header'ları şunlardır:
- Content-Type: Media type'ı tahmin etmek için
- Content-Location veya X-Original-URL: Preview/correlation için original remote URL
- Content-Encoding: gzip/deflate/br (Brotli) olabilir

Media, header'lar body'den ayrılarak ve isteğe bağlı olarak Content-Encoding'e göre decompress edilerek extract edilebilir. Content-Type mevcut olmadığında magic-byte sniffing yararlıdır.

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: https://github.com/jwdfir/discord_cache_parser
- Function: Discord'un cache folder'ını recursive olarak scan eder, webhook/API/attachment URL'lerini bulur, f_* body'lerini parse eder, isteğe bağlı olarak media carve eder ve SHA‑256 hash'leriyle HTML + CSV timeline report'ları oluşturur.<sup>[[2]](#references)</sup>

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
- --timeline: Sıralı CSV zaman çizelgesi oluşturur (değiştirilme zamanına göre)
- --extra: Kardeş Code Cache ve GPUCache dizinlerini de tarar
- --carve: Regex eşleşmelerinin yakınındaki ham byte'lardan medya ayıklar (görseller/video)
- Çıktı: HTML raporu, CSV raporu, CSV zaman çizelgesi ve ayıklanan/çıkarılan dosyaların bulunduğu bir medya klasörü

## Analist ipuçları

- Bir zaman çizelgesi oluşturmak için f_* ve data_* dosyalarının değiştirilme zamanlarını (mtime) kullanıcı/attacker etkinlik zaman aralıklarıyla ilişkilendirin.
- Kurtarılan medyaları hash'leyin (SHA-256) ve bilinen zararlı veya exfil veri kümeleriyle karşılaştırın.
- Çıkarılan webhook URL'leri canlılık açısından test edilebilir veya döndürülebilir; bunları blocklist'lere eklemeyi ve proxy'lerde retro-hunting yapmayı değerlendirin.
- Cache, server tarafında “silindikten” sonra da kalıcı olur. Acquisition mümkünse Cache dizininin tamamını ve ilgili kardeş cache'leri (Code Cache, GPUCache) toplayın.<sup>[[1]](#references)</sup>

## Referanslar

- [1] [C2 olarak Discord ve geride bıraktığı cache kanıtları](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [2] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [3] [Discord Webhook'ları - Webhook'u çalıştırma](https://discord.com/developers/docs/resources/webhook#execute-webhook)

{{#include ../../../banners/hacktricks-training.md}}
