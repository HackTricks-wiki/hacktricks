# AGENTS.md

Bu repository üzerinde çalışacak gelecekteki agent'lar için rehber.

## Repository Context

Bu, ana HackTricks mdBook repository'sidir. İlgili cloud book şu konumda bulunur:

`/Users/carlospolop/git/hacktricks-cloud`

Paylaşılan theme/search davranışındaki değişikliklerin genellikle her iki repository'ye de uygulanması gerekir.

## Search Index Loading Contract

Özel search UI şu konumda bulunur:

`theme/ht_searcher.js`

Ayrıca oluşturulmuş bir kopya da şu konumda bulunabilir:

`book/theme/ht_searcher.js`

Production zaten oluşturulmuş `book/` directory'sini deploy ediyorsa her iki kopyayı da güncelleyin veya deployment öncesinde book'u yeniden oluşturun.

Search index kaynak politikası önemlidir ve maliyete duyarlıdır:

- Public host'larda her language-specific ve fallback candidate'ı yalnızca
`HackTricks-wiki/hacktricks-searchindex` üzerinden yükleyin. Aynı-origin mdBook output'una hiçbir zaman fallback yapmayın; production'da büyük index'i `hacktricks.wiki` üzerinden sunmak maliyetlidir.
- Localhost, `.local`/`.internal` host'larında, loopback, RFC1918, carrier-grade NAT, link-local veya private IPv6 adreslerinde yalnızca aynı-origin mdBook output'unu yükleyin; böylece local/container deployment'ları self-contained kalır. English olmayan bir page için önce language-prefixed local path'i deneyin (örneğin `/es/searchindex.js`) ve root English index'i yalnızca fallback olarak kullanın.

Bu repo için beklenen local fallback:

`/searchindex.js`

Private host'larda cloud index bu origin'den kullanılamaz ve remote download'ı tetiklememelidir. Public host'larda `searchindex-cloud-<lang>.js.gz` dosyalarını remote olarak kullanmalıdır.

## Search Index Publishing

Encrypted compressed search index'lerini `HackTricks-wiki/hacktricks-searchindex` repository'sine publish eden workflow'lar şunlardır:

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

Oluşturulan source file `book/searchindex.js`'dir. Publish edilen remote artifact adları şunlardır:

- `searchindex-v2-en.json.gz` (tercih edilen compact index)
- `searchindex-v2-<lang>.json.gz` (tercih edilen compact index)
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

Browser loader compact v2 artifact'ını tercih eder ve `.js.gz` artifact'ını legacy fallback olarak tutar. Her ikisi de `theme/ht_searcher.js` içinde tanımlanan key kullanılarak XOR-encrypted gzip payload'larıdır.

Loader lazy kalmalıdır: normal page navigation, visitor search'ü açana veya kullanana kadar search worker oluşturmamalı ya da index download etmemelidir. Remote compressed response'lar origin başına 24 saat boyunca Cache Storage'da saklanır; böylece sonraki page'ler bunları yeniden kullanabilir. Süresi dolmuş bir entry'yi yenileme başarısız olduğunda stale-cache fallback'ini koruyun.

## Build And Validation

Yaygın local kontroller:

- `node --check theme/ht_searcher.js`
- `mdbook build`

`mdbook build` başarısız olursa şunları kontrol edin:

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Editing Notes

- Arama yapmak için `rg` kullanmayı tercih edin.
- Açıkça istenmediği sürece oluşturulan `book/` output'unu commit'lere dahil etmeyin. Zaten oluşturulmuş page'lerin hemen düzeltilmesi gerektiğinde search loader düzeltmeleri istisnadır.
- Paylaşılan theme davranışını değiştiriyorsanız `/Users/carlospolop/git/hacktricks-cloud` içindeki eşleşen file'ı karşılaştırın ve güncelleyin.
- İlgisiz local değişiklikleri geri almayın.
