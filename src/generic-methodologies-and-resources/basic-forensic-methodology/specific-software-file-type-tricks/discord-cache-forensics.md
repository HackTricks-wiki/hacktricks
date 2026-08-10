# Discord Cache Forensics (Chromium Disk Cache)

Bu sayfa, yerel olarak önbelleğe alınmış medyalar, webhook endpoint'leri ve etkinlik korelasyonu için Discord Desktop cache artifact'larının nasıl triage edileceğini özetler. Discord'un desktop client'ı Electron kullanır ve Electron, disk cache gibi session verilerini `sessionData` altında depolar.<sup>[[3]](#references)[[4]](#references)</sup>

## Bakılacak yerler (Windows/macOS/Linux)

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

Bunlar, başvurulan parser tarafından kullanılan varsayılan yollardır; Electron bir uygulamanın `sessionData` değerini override etmesine izin verir, bu nedenle acquisition sırasında gerçek profile path'ini doğrulayın.<sup>[[2]](#references)[[4]](#references)</sup>

`index` + `data_#` + `f_######` düzeni, Chromium'un blockfile disk-cache backend'i ile eşleşir; Chromium farklı cache implementasyonlarını belgelediğinden, backend'i doğrulamadan bunu Simple Cache olarak adlandırmayın.<sup>[[5]](#references)</sup>

`Cache_Data` içindeki önemli on-disk yapılar:
- `index`: Entry'leri bulmak için kullanılan Blockfile cache index'i.
- `data_#`: Cache metadata'sı, HTTP header'ları ve response data içerebilen sabit boyutlu block dosyaları.
- `f_######`: Block-file limitinden daha büyük veriler için kullanılan ayrı dosyalar; bu dosyalar block-file header'ları olmadan depolanan veriyi içerir.

Mesajların, channel'ların veya server'ların silinmesi, yerel olarak zaten cache'lenmiş byte'ların kaldırılacağını garanti etmez; ancak Chromium cache dosyalarını istediği zaman evict edebilir veya yeniden oluşturabilir. Kalan artifact'ları fırsatçı evidence olarak değerlendirin ve file modification time değerlerini yalnızca diğer telemetry ile korele edilmesi gereken yaklaşık local-write sinyalleri olarak kullanın.<sup>[[5]](#references)[[6]](#references)</sup>

## Neler kurtarılabilir

Ne alınmış olduğuna ve henüz evict edilip edilmediğine bağlı olarak triage; cache'lenmiş attachment'ları, medyaları, URL'leri ve file hash'lerini kurtarabilir; yalnızca cache, bir öğenin exfiltrate edildiğini kanıtlamaz.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Discord CDN URL'leri tarafından referans verilen attachment'lar ve thumbnail'ler.
- Görseller, GIF'ler ve videolar (örneğin `.jpg`, `.png`, `.gif`, `.webp`, `.mp4` ve `.webm`).
- `https://discord.com/api/webhooks/...` gibi webhook URL'leri.<sup>[[2]](#references)[[7]](#references)</sup>
- `https://discord.com/api/vX/...` gibi Discord API çağrıları.<sup>[[2]](#references)</sup>
- Kurtarılan medyaları bilinen dataset'ler veya intelligence feed'leri ile karşılaştırmak için SHA-256 hash'leri.<sup>[[1]](#references)[[2]](#references)</sup>

## Hızlı triage (manuel)

- Cache'i high-signal artifact'lar için Grep ile tarayın. Bu pattern'ler, başvurulan parser'ın URL expression'larını yansıtır ve exhaustive indicator'lar değil, triage filter'larıdır.<sup>[[2]](#references)</sup>
- Webhook endpoint'leri:
- Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
- Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
- Attachment/CDN URL'leri:
- strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
- Discord API çağrıları:
- strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Yaklaşık bir sequence oluşturmak için cache'lenmiş entry'leri modified time'a göre sıralayın; mtime bir filesystem sinyalidir ve tek başına bir Discord object'inin ne zaman fetch edildiğini veya gönderildiğini ortaya koymaz.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## `f_*` entry'lerini parse etme (HTTP body + headers)

Blockfile düzeninde `f_######` dosyaları ayrı data stream'leridir ve tam bir HTTP response ile başlamaları garanti edilmez. Acquired bir dosya, `\r\n\r\n` sonrasında serialized HTTP header'ları içeriyorsa, ilk delimiter'dan bölün ve inceleyin:<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type: Media type'ını tahmin etmek için
- Content-Location veya X-Original-URL: Preview/correlation için original remote URL
- Content-Encoding: gzip/deflate/br (Brotli) olabilir.

Media daha sonra header'lar body'den ayrılarak ve isteğe bağlı olarak `Content-Encoding` değerine göre decompress edilerek extract edilebilir; başvurulan parser Brotli, gzip ve deflate'i destekler. `Content-Type` mevcut olmadığında magic-byte sniffing faydalıdır, ancak bir heuristic olarak kalır.<sup>[[2]](#references)</sup>

## Automated DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: [Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser).<sup>[[1]](#references)</sup>
- Function: Discord'un cache folder'ını recursive olarak tarar, webhook/API/attachment URL'lerini bulur, `f_*` body'lerini parse eder, isteğe bağlı olarak media carve eder ve optional chronological timeline ile SHA-256 hash'lerini içeren HTML ve CSV report'ları output eder.<sup>[[1]](#references)[[2]](#references)</sup>

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
CLI, bu seçenekleri ve çıktı adlarını tanımlar:<sup>[[2]](#references)</sup>
- --cache: Discord Cache_Data dizininin yolu
- --format html|csv|both
- --timeline: Sıralı CSV zaman çizelgesi oluşturur (değiştirilme zamanına göre)
- --extra: Kardeş Code Cache ve GPUCache dizinlerini de tarar
- --carve: Tanınan media imzalarını (images/video) kullanarak ham cache baytlarından media çıkarır
- Output: `<output>.html`, `<output>.csv`, isteğe bağlı `<output>_timeline.csv` ve çıkarılan veya carve edilen dosyaları içeren bir `<output>_media` klasörü.

## Analyst tips

- `f_*` ve `data_*` dosyalarının değiştirilme zamanını (mtime) kullanıcı veya attacker etkinlik zaman aralıkları ve bağımsız telemetry ile ilişkilendirin; mtime kesin bir olay zaman damgası değildir.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Kurtarılan media dosyalarının hash değerlerini (SHA-256) alın ve bilinen kötü amaçlı veya exfiltration veri kümeleriyle karşılaştırın.<sup>[[1]](#references)[[2]](#references)</sup>
- Çıkarılan webhook URL'lerini credential olarak değerlendirin. Yalnızca erişilebilirliklerini test etmek için bunları çağırmayın; güvenli şekilde koruyun, revocation veya rotation işlemlerini koordine edin ve retro-hunting için ilgili network telemetry verilerini kullanın.<sup>[[7]](#references)</sup>
- Server-side deletion işlemi, yerel cache baytlarının yok edildiğini garanti etmez. Acquisition mümkünse, eviction veya cache recreation gerçekleşmeden önce tüm `Cache` dizinini ve ilgili kardeş cache dizinlerini (`Code Cache`, `GPUCache`) toplayın.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [2] [Discord Forensic Suite CLI](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [Discord'un Milyonlarca Kullanıcıyı 64-Bit Architecture'a Sorunsuz Şekilde Yükseltmesi](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [app | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [Disk Cache](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [C2 olarak Discord ve geride bıraktığı cache kanıtları](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Discord Webhooks – Execute Webhook](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
