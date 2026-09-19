# AGENTS.md

Bu repository üzerinde çalışan gelecekteki agent'lar için rehber.

## Repository Context

Bu, ana HackTricks mdBook repository'sidir. İlgili cloud book şu konumda bulunur:

`/Users/carlospolop/git/hacktricks-cloud`

Paylaşılan theme/search davranışındaki değişikliklerin çoğu her iki repository'ye de uygulanmalıdır.

## Search Index Loading Contract

Özel search UI şu konumda bulunur:

`theme/ht_searcher.js`

Ayrıca oluşturulmuş bir kopya şu konumda bulunabilir:

`book/theme/ht_searcher.js`

Production, önceden oluşturulmuş `book/` directory'sini deploy ediyorsa her iki kopyayı da güncelleyin veya book'u yeniden oluşturun.

Search index loading sırası önemlidir ve maliyete duyarlıdır:

1. GitHub repository'sinden her language-specific ve fallback search index'ini yükleyin:
`HackTricks-wiki/hacktricks-searchindex`
2. Yalnızca GitHub-hosted tüm adaylar başarısız olursa aynı-origin mdBook output'una fallback yapın.

Local `/searchindex.js` fallback'ini, `searchindex-en.js.gz` gibi GitHub-hosted herhangi bir fallback'in önüne koymayın. Production'da `searchindex.js` dosyasını `hacktricks.wiki` üzerinden sunmak maliyetlidir.

Bu repo için beklenen local fallback:

`/searchindex.js`

Cloud index, bu origin'den bir local fallback kullanmamalıdır. Remote `searchindex-cloud-<lang>.js.gz` dosyalarına güvenmelidir.

## Search Index Publishing

Encrypted compressed search index'lerini `HackTricks-wiki/hacktricks-searchindex` repository'sine publish eden workflow'lar şunlardır:

- `.github/workflows/build_master.yml`
- `.github/workflows/translate_all.yml`

Oluşturulan source file `book/searchindex.js` dosyasıdır. Publish edilen remote artifact adları şunlardır:

- `searchindex-v2-en.json.gz` (preferred compact index)
- `searchindex-v2-<lang>.json.gz` (preferred compact index)
- `searchindex-en.js.gz`
- `searchindex-<lang>.js.gz`

Browser loader, compact v2 artifact'ını tercih eder ve `.js.gz` artifact'ını legacy fallback olarak korur. Her ikisi de `theme/ht_searcher.js` içinde tanımlanan key kullanılarak XOR-encrypted gzip payload'larıdır.

Loader lazy kalmalıdır: normal page navigation, ziyaretçi search'ü açana veya kullanana kadar search worker oluşturmamalı ya da bir index indirmemelidir. Remote compressed response'lar origin başına 24 saat boyunca Cache Storage'da saklanır; böylece sonraki sayfalar bunları yeniden kullanabilir. Süresi dolmuş bir entry'yi yenileme başarısız olduğunda stale-cache fallback'ini koruyun.

## Build And Validation

Yaygın local kontroller:

- `node --check theme/ht_searcher.js`
- `mdbook build`

`mdbook build` başarısız olursa şunları kontrol edin:

- `hacktricks-preprocessor-error.log`
- `hacktricks-preprocessor.log`

## Editing Notes

- Arama yapmak için `rg` kullanmayı tercih edin.
- Açıkça istenmediği sürece oluşturulmuş `book/` output'unu commit'lere dahil etmeyin. Zaten oluşturulmuş sayfaların hemen düzeltilmesi gerektiğinde search loader düzeltmeleri istisnadır.
- Paylaşılan theme davranışını değiştiriyorsanız `/Users/carlospolop/git/hacktricks-cloud` içindeki eşleşen dosyayı karşılaştırın ve güncelleyin.
- İlgisiz local değişiklikleri geri almayın.
