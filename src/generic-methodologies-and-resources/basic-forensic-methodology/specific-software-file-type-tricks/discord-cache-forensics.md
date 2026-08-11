# Discord Cache Forensics (Chromium Disk Cache)

{{#include ../../../banners/hacktricks-training.md}}

Bu sayfa, yerel olarak cache'lenmiş medya, webhook endpoint'leri ve etkinlik korelasyonu için Discord Desktop cache artifact'larının nasıl triage edileceğini özetler. Discord'un desktop client'ı Electron kullanır ve Electron, disk cache gibi session verilerini `sessionData` altında saklar.<sup>[[3]](#references)[[4]](#references)</sup>

## Nereye bakılmalı (Windows/macOS/Linux)

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

Bunlar, referans alınan parser tarafından kullanılan varsayılan path'lerdir; Electron bir uygulamanın `sessionData` değerini override etmesine izin verdiğinden acquisition sırasında gerçek profile path'ini doğrulayın.<sup>[[2]](#references)[[4]](#references)</sup>

`index` + `data_#` + `f_######` düzeni, Chromium'un blockfile disk-cache backend'iyle eşleşir; Chromium farklı cache implementation'larını belgelediğinden backend'i doğrulamadan bunu Simple Cache olarak etiketlemeyin.<sup>[[5]](#references)</sup>

`Cache_Data` içindeki temel on-disk yapılar:
- `index`: Entry'leri bulmak için kullanılan Blockfile cache index'i.
- `data_#`: Cache metadata'sı, HTTP header'ları ve response data içerebilen sabit boyutlu block file'ları.
- `f_######`: Block-file limitinden büyük data için kullanılan ayrı file'lar; bu file'lar block-file header'ları olmadan saklanan data'yı içerir.

Mesajların, channel'ların veya server'ların silinmesi, yerel olarak cache'lenmiş byte'ların kaldırılmasını garanti etmez; ancak Chromium cache file'larını istediği zaman evict edebilir veya yeniden oluşturabilir. Hayatta kalan artifact'ları fırsata bağlı evidence olarak değerlendirin ve file modification time değerlerini yalnızca diğer telemetry ile korele edilmesi gereken yaklaşık yerel yazma sinyalleri olarak kullanın.<sup>[[5]](#references)[[6]](#references)</sup>

## Neler kurtarılabilir

Ne fetch edildiğine ve henüz evict edilip edilmediğine bağlı olarak triage, cache'lenmiş attachment'ları, medya dosyalarını, URL'leri ve file hash'lerini kurtarabilir; yalnızca cache, bir item'ın exfiltrate edildiğini kanıtlamaz.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Discord CDN URL'lerinde referans verilen attachment'lar ve thumbnail'ler.
- Images, GIF'ler ve videolar (örneğin `.jpg`, `.png`, `.gif`, `.webp`, `.mp4` ve `.webm`).
- `https://discord.com/api/webhooks/...` gibi webhook URL'leri.<sup>[[2]](#references)[[7]](#references)</sup>
- `https://discord.com/api/vX/...` gibi Discord API çağrıları.<sup>[[2]](#references)</sup>
- Kurtarılan medyanın bilinen dataset'ler veya intelligence feed'leriyle karşılaştırılması için SHA-256 hash'leri.<sup>[[1]](#references)[[2]](#references)</sup>

## Hızlı triage (manuel)

- Yüksek sinyalli artifact'lar için cache üzerinde Grep çalıştırın. Bu pattern'ler, referans alınan parser'ın URL expression'larını yansıtır; exhaustive indicator değildir.<sup>[[2]](#references)</sup>
- Webhook endpoint'leri:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URL'leri:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
- Discord API çağrıları:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Yaklaşık bir sequence oluşturmak için cache'lenmiş entry'leri modified time'a göre sıralayın; mtime bir filesystem sinyalidir ve tek başına bir Discord object'inin ne zaman fetch edildiğini veya gönderildiğini belirlemez.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## f_* entry'lerini parse etme (HTTP body + headers)

Blockfile düzeninde `f_######` file'ları ayrı data stream'leridir ve tam bir HTTP response ile başlamaları garanti edilmez. Acquired bir file, `\r\n\r\n` sonrasında serialized HTTP header'ları içeriyorsa ilk delimiter'dan bölün ve inceleyin:<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type: Media type'ını tahmin etmek için
- Content-Location veya X-Original-URL: Preview/correlation için orijinal remote URL
- Content-Encoding: gzip/deflate/br (Brotli) olabilir.

Ardından header'lar body'den ayrılarak ve isteğe bağlı olarak `Content-Encoding` değerine göre decompress edilerek medya extract edilebilir; referans alınan parser Brotli, gzip ve deflate'i destekler. `Content-Type` mevcut olmadığında magic-byte sniffing yararlıdır, ancak bu yine de bir heuristic'tir.<sup>[[2]](#references)</sup>

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: [Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser).<sup>[[1]](#references)</sup>
- Function: Discord'un cache folder'ını recursive olarak tarar, webhook/API/attachment URL'lerini bulur, `f_*` body'lerini parse eder, isteğe bağlı olarak medyayı carve eder ve SHA-256 hash'leriyle birlikte HTML ve CSV report'ları ile isteğe bağlı chronological timeline çıktısı oluşturur.<sup>[[1]](#references)[[2]](#references)</sup>

Örnek CLI kullanımı:
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
CLI şu seçenekleri ve çıktı adlarını tanımlar:<sup>[[2]](#references)</sup>
- --cache: Discord Cache_Data dizininin yolu
- --format html|csv|both
- --timeline: Sıralı CSV zaman çizelgesi oluşturur (değiştirilme zamanına göre)
- --extra: Kardeş Code Cache ve GPUCache dizinlerini de tarar
- --carve: Tanınan medya imzalarını (görseller/video) kullanarak ham cache baytlarından medya çıkarır
- Çıktı: `<output>.html`, `<output>.csv`, isteğe bağlı `<output>_timeline.csv` ve çıkarılan veya carve edilen dosyaları içeren bir `<output>_media` klasörü.

## Analyst tips

- `f_*` ve `data_*` dosyalarının değiştirilme zamanını (mtime) kullanıcı veya saldırgan etkinliği zaman aralıkları ve bağımsız telemetriyle ilişkilendirin; mtime kesin bir olay zaman damgası değildir.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Kurtarılan medyanın hash değerini (SHA-256) hesaplayın ve bilinen kötü amaçlı içerik veya exfiltration veri kümeleriyle karşılaştırın.<sup>[[1]](#references)[[2]](#references)</sup>
- Çıkarılan webhook URL'lerini kimlik bilgileri olarak değerlendirin. Bunları yalnızca çalışırlıklarını test etmek için çağırmayın; güvenli şekilde koruyun, iptal veya rotation işlemlerini koordine edin ve geçmiş tehdit avcılığı için ilişkili ağ telemetrisi kullanın.<sup>[[7]](#references)</sup>
- Sunucu tarafında silme işlemi, yerel cache baytlarının yok edildiğini garanti etmez. Acquisition mümkünse, eviction veya cache yeniden oluşturulmadan önce `Cache` dizininin tamamını ve ilişkili kardeş cache'leri (`Code Cache`, `GPUCache`) toplayın.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [2] [Discord Forensic Suite CLI](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [Discord'un Milyonlarca Kullanıcıyı 64-Bit Mimarisi'ne Sorunsuzca Yükseltmesi](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [app | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [Disk Cache](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [Discord as a C2 and the cached evidence left behind](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
