# macOS R Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `R_PROFILE_USER` / `R_PROFILE`

Başlangıçta R, R kodu içeren site ve kullanıcı profile dosyalarını kaynak olarak kullanır. `R_PROFILE` site profilini, `R_PROFILE_USER` ise kullanıcı profilini seçer; böylece devralınan bir ortam, bu aramalardan herhangi birini saldırganın okuyabildiği bir dosyaya yönlendirebilir.<sup>[[1]](#references)</sup>
```bash
echo 'file.create("/tmp/r-profile-executed")' >/tmp/attacker.Rprofile
R_PROFILE_USER=/tmp/attacker.Rprofile Rscript victim.R
```
`--no-init-file` kullanıcı profilini, `--no-site-file` site profilini atlar ve `--vanilla` her iki korumayı da etkinleştirir. R önce `R_ENVIRON` ve `R_ENVIRON_USER` tarafından seçilen environment dosyalarını işler; ancak bu dosyalar yalnızca değişkenleri ayarlar. Profile değişkenleri, doğrudan arbitrary-code primitive'idir.

## `R_DEFAULT_PACKAGES` / `R_SCRIPT_DEFAULT_PACKAGES` ve library paths

R, başlangıç sırasında `R_DEFAULT_PACKAGES` içindeki virgülle ayrılmış paketleri attach eder. `Rscript`, `R_SCRIPT_DEFAULT_PACKAGES` değişkenine öncelik verir. Bu değişkenlerden herhangi birini `R_LIBS`, `R_LIBS_USER` veya `R_LIBS_SITE` ile birleştirmek, R'nin attacker-controlled ve yüklenmiş bir paketi bulup yüklemesine neden olabilir; paketin `.onLoad` veya `.onAttach` hook'u otomatik olarak çalışır.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Assume an installed package named htpayload exists below /tmp/r-library.
R_LIBS_USER=/tmp/r-library \
R_DEFAULT_PACKAGES=htpayload \
R --no-save --no-restore --silent

R_LIBS_USER=/tmp/r-library \
R_SCRIPT_DEFAULT_PACKAGES=htpayload \
Rscript victim.R
```
Bu işlem yalnızca bağımsız bir `.R` dosyası değil, yapısal olarak geçerli ve kurulu bir R package gerektirir. `--vanilla`, doğrudan miras alınan değişkenleri temizlemez; bu nedenle güvenilir bir wrapper, profil dosyalarını devre dışı bırakmanın yanı sıra varsayılan package ve library-path değişkenlerini de kaldırmalı veya değiştirmelidir.

## References

- [1] [Bir R Oturumunun Başlangıcında Başlatma](https://stat.ethz.ch/R-manual/R-devel/library/base/html/Startup.html)
- [2] [R Kurulumu ve Yönetimi: Eklenti package'ları](https://stat.ethz.ch/CRAN/doc/manuals/r-release/R-admin.html)
{{#include ../../../banners/hacktricks-training.md}}
