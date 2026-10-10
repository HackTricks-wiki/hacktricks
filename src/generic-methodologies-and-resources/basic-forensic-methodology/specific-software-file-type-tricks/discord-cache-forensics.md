# Discord Cache Forensics (Chromium Disk Cache)

{{#include ../../../banners/hacktricks-training.md}}

Bu sayfa, yerel olarak önbelleğe alınmış medya, webhook endpoint'leri ve etkinlik korelasyonu için Discord Desktop cache artifact'lerinin nasıl triage edileceğini özetler. Discord masaüstü istemcisi Electron kullanır ve Electron, disk cache gibi oturum verilerini `sessionData` altında depolar.<sup>[[3]](#references)[[4]](#references)</sup>

## Bakılacak yerler (Windows/macOS/Linux)

- Windows: `%AppData%\discord\Cache\Cache_Data`
- macOS: `~/Library/Application Support/discord/Cache/Cache_Data`
- Linux: `~/.config/discord/Cache/Cache_Data`

Bunlar, belirtilen parser tarafından kullanılan varsayılan yollardır; Electron bir uygulamanın `sessionData` yolunu değiştirmesine izin verir, bu nedenle edinim sırasında gerçek profil yolunu doğrulayın.<sup>[[2]](#references)[[4]](#references)</sup>

`index` + `data_#` + `f_######` düzeni, Chromium'un blockfile disk-cache backend'iyle eşleşir; backend'i doğrulamadan Simple Cache olarak adlandırmayın, çünkü Chromium farklı cache uygulamalarını belgeliyor.<sup>[[5]](#references)</sup>

`Cache_Data` içindeki temel disk yapıları:
- `index`: Girdileri bulmak için kullanılan Blockfile cache index'i.
- `data_#`: Cache metadata'sı, HTTP header'ları ve yanıt verileri içerebilen sabit boyutlu block dosyaları.
- `f_######`: Block dosyası sınırından büyük veriler için kullanılan ayrı dosyalar; bu dosyalar block-file header'ları olmadan depolanan verileri içerir.

Mesajların, kanalların veya sunucuların silinmesi, yerel olarak önbelleğe alınmış byte'ların kaldırılacağını garanti etmez; ancak Chromium cache dosyalarını istediği zaman silebilir veya yeniden oluşturabilir. Hayatta kalan artifact'leri fırsatçı kanıtlar olarak değerlendirin ve dosya değiştirilme zamanlarını yalnızca diğer telemetriyle korelasyon kurulması gereken yaklaşık yerel yazma sinyalleri olarak kullanın.<sup>[[5]](#references)[[6]](#references)</sup>

## Neler kurtarılabilir

Nelerin getirildiğine ve henüz silinip silinmediğine bağlı olarak triage; önbelleğe alınmış ekleri, medyayı, URL'leri ve dosya hash'lerini kurtarabilir; ancak cache tek başına bir öğenin dışarı sızdırıldığını kanıtlamaz.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

- Discord CDN URL'lerinde referans verilen ekler ve küçük resimler.
- Görseller, GIF'ler ve videolar (örneğin `.jpg`, `.png`, `.gif`, `.webp`, `.mp4` ve `.webm`).
- `https://discord.com/api/webhooks/...` gibi webhook URL'leri.<sup>[[2]](#references)[[7]](#references)</sup>
- `https://discord.com/api/vX/...` gibi Discord API çağrıları.<sup>[[2]](#references)</sup>
- Kurtarılan medyanın bilinen veri kümeleri veya istihbarat akışlarıyla karşılaştırılması için SHA-256 hash'leri.<sup>[[1]](#references)[[2]](#references)</sup>

## Hızlı triage (manuel)

- Cache'te yüksek sinyalli artifact'leri grep ile arayın. Bu desenler, belirtilen parser'ın URL ifadelerini yansıtır ve kapsamlı göstergeler değil, triage filtreleridir.<sup>[[2]](#references)</sup>
  - Webhook endpoint'leri:
    - Windows: findstr /S /I /C:"https://discord.com/api/webhooks/" "%AppData%\discord\Cache\Cache_Data\*"
    - Linux/macOS: strings -a Cache_Data/* | grep -i "https://discord.com/api/webhooks/"
  - Ek/CDN URL'leri:
    - strings -a Cache_Data/* | grep -Ei "https://(cdn|media)\.discordapp\.com/attachments/"
  - Discord API çağrıları:
    - strings -a Cache_Data/* | grep -Ei "https://discord(app)?\.com/api/v[0-9]+/"
- Yaklaşık bir sıralama oluşturmak için önbelleğe alınmış girdileri değiştirilme zamanına göre sıralayın; mtime bir dosya sistemi sinyalidir ve tek başına bir Discord nesnesinin ne zaman getirildiğini veya gönderildiğini göstermez.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
  - Windows PowerShell: Get-ChildItem "$env:AppData\discord\Cache\Cache_Data" -File -Recurse | Sort-Object LastWriteTime | Select-Object LastWriteTime, FullName

## f_* girdilerini ayrıştırma (HTTP gövdesi + header'lar)

Blockfile düzeninde `f_######` dosyaları ayrı veri akışlarıdır ve eksiksiz bir HTTP yanıtıyla başlamaları garanti değildir. Edinilen bir dosya, `\r\n\r\n` sonrasında sıralanmış HTTP header'ları içeriyorsa ilk ayırıcıda bölün ve şunları inceleyin:<sup>[[2]](#references)[[5]](#references)</sup>
- Content-Type: Medya türünü tahmin etmek için
- Content-Location veya X-Original-URL: Önizleme/korelasyon için orijinal uzak URL
- Content-Encoding: gzip/deflate/br (Brotli) olabilir.

Daha sonra header'lar gövdeden ayrılarak ve isteğe bağlı olarak `Content-Encoding` değerine göre sıkıştırma açılarak medya çıkarılabilir; belirtilen parser Brotli, gzip ve deflate'i işler. `Content-Type` olmadığında magic-byte incelemesi yararlıdır, ancak yine de sezgisel bir yöntemdir.<sup>[[2]](#references)</sup>

## Otomatik DFIR: Discord Forensic Suite (CLI/GUI)

- Repo: [Discord Forensic Suite](https://github.com/jwdfir/discord_cache_parser).<sup>[[1]](#references)</sup>
- İşlev: Discord'un cache klasörünü özyinelemeli olarak tarar, webhook/API/ek URL'lerini bulur, `f_*` gövdelerini ayrıştırır, isteğe bağlı olarak medyayı carve eder ve HTML ile CSV raporlarının yanı sıra SHA-256 hash'leri içeren isteğe bağlı kronolojik bir zaman çizelgesi oluşturur.<sup>[[1]](#references)[[2]](#references)</sup>

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
- --carve: Tanınan medya imzalarını (görsel/video) kullanarak ham cache baytlarından medya carve işlemi yapar
- Çıktı: `<output>.html`, `<output>.csv`, isteğe bağlı `<output>_timeline.csv` ve çıkarılmış veya carve edilmiş dosyaları içeren bir `<output>_media` klasörü.

## Analist ipuçları

- `f_*` ve `data_*` dosyalarının değiştirilme zamanlarını (mtime) kullanıcı veya saldırgan etkinliği zaman aralıkları ve bağımsız telemetriyle ilişkilendirin; mtime kesin bir olay zaman damgası değildir.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>
- Kurtarılan medyaların hash'ini (SHA-256) alın ve bilinen kötü amaçlı içerik veya veri sızdırma veri kümeleriyle karşılaştırın.<sup>[[1]](#references)[[2]](#references)</sup>
- Çıkarılan webhook URL'lerini kimlik bilgileri olarak değerlendirin. Çalışıp çalışmadıklarını sınamak için bu URL'leri kullanmayın; güvenli biçimde saklayın, iptal veya yenileme işlemlerini koordine edin ve geriye dönük tehdit avcılığı için ilgili ağ telemetrisinden yararlanın.<sup>[[7]](#references)</sup>
- Sunucu tarafında silme işlemi, yerel olarak cache'lenmiş baytların yok edildiğini garanti etmez. Edinim mümkünse, temizlenmeden veya cache yeniden oluşturulmadan önce `Cache` dizininin tamamını ve ilgili kardeş cache'leri (`Code Cache`, `GPUCache`) toplayın.<sup>[[2]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [Discord Forensic Suite (CLI/GUI)](https://github.com/jwdfir/discord_cache_parser)
- [2] [Discord Forensic Suite CLI](https://raw.githubusercontent.com/jwdfir/discord_cache_parser/refs/heads/main/discord_forensic_suite_cli)
- [3] [Discord'un Milyonlarca Kullanıcıyı 64 Bit Mimarisiyle Sorunsuz Bir Şekilde Nasıl Yükselttiği](https://discord.com/blog/how-discord-seamlessly-upgraded-millions-of-users-to-64-bit-architecture)
- [4] [app | Electron](https://www.electronjs.org/docs/latest/api/app)
- [5] [Disk Cache](https://www.chromium.org/developers/design-documents/network-stack/disk-cache/)
- [6] [Discord'u C2 Olarak Kullanmak ve Geride Bıraktığı Cache Kanıtları](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- [7] [Discord Webhooks – Webhook'u Çalıştırma](https://discord.com/developers/docs/resources/webhook#execute-webhook)
{{#include ../../../banners/hacktricks-training.md}}
