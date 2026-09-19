# AGENTS.md

Bu repository üzerinde çalışacak gelecekteki agent'lar için rehber.

## Repository Context

Bu, ana HackTricks mdBook repository'sidir. İlgili cloud book şu konumda bulunur:

`/Users/carlospolop/git/hacktricks-cloud`

Paylaşılan theme/search davranışındaki değişikliklerin genellikle her iki repository'ye de uygulanması gerekir.

## Search Index Loading Contract

Özel search UI şu konumda bulunur:

`theme/ht_searcher.js`

Ayrıca oluşturulmuş bir kopya şu konumda bulunabilir:

`book/theme/ht_searcher.js`

Production zaten oluşturulmuş `book/` directory'sini deploy ediyorsa her iki kopyayı da güncelleyin veya book'u yeniden build edin.

Search index source policy önemlidir ve maliyete duyarlıdır:

- Public host'larda her language-specific ve fallback candidate'ı yalnızca
`HackTricks-wiki/hacktricks-searchindex` üzerinden yükleyin. Aynı-origin mdBook output'una fallback yapmayın; production'da büyük index'i `hacktricks.wiki` üzerinden sunmak maliyetlidir.
- Localhost, `.local`/`.internal` host'larda, loopback, RFC1918, carrier-grade NAT, link-local veya private IPv6 address'lerinde yalnızca aynı-origin mdBook output'unu yükleyin; böylece local/container deployment'lar self-contained kalır.

Bu repo için beklenen local fallback:

`/searchindex.js`

Private host'larda cloud index bu origin üzerinden kullanılamaz ve remote download tetiklenmemelidir. Public host'larda `searchindex-cloud-<lang>.js.gz` dosyalarını remote olarak kullanmalıdır.

## Search Index Publishing

Şifrelenmiş sıkıştırılmış search index'lerini
`HackTricks-wiki/hacktricks-searchindex` repository'sine publish eden workflow'lar şunlardır:

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

Oluşturulan source file `book/searchindex.js` dosyasıdır. Publish edilen remote artifact isimleri şunlardır:

- `searchindex-v2-en.json.gz` (preferred compact index)
- `searchindex-v2-<lang>.json.gz` (preferred compact index)
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

Browser loader compact v2 artifact'ını tercih eder ve `.js.gz` artifact'ını legacy fallback olarak korur. Her ikisi de `theme/ht_searcher.js` içinde tanımlanan key kullanılarak XOR-encrypted gzip payload'larıdır.

Loader lazy kalmalıdır: normal page navigation, visitor search'ü açana veya kullanana kadar search worker oluşturmamalı ya da index download etmemelidir. Remote compressed response'lar origin başına 24 saat boyunca Cache Storage'da tutulur; böylece sonraki sayfalar bunları yeniden kullanabilir. Expired entry yenilenemediğinde stale-cache fallback'i koruyun.

## Build And Validation

Yaygın local kontroller:

- `node --check theme/ht_searcher.js`
- `mdbook build`

`mdbook build` başarısız olursa şunları kontrol edin:

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Editing Notes

- Arama yapmak için `rg` kullanmayı tercih edin.
- Açıkça istenmediği sürece oluşturulan `book/` output'unu commit'lere dahil etmeyin. Zaten oluşturulmuş sayfaların hemen düzeltilmesi gerektiğinde search loader düzeltmeleri istisnadır.
- Paylaşılan theme davranışını değiştiriyorsanız `/Users/carlospolop/git/hacktricks-cloud` içindeki eşleşen dosyayı karşılaştırın ve güncelleyin.
- İlgisiz local değişiklikleri geri almayın.
