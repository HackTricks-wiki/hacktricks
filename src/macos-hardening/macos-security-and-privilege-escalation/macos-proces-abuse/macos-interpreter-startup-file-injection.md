# macOS Interpreter Başlangıç Enjeksiyonu Ortam Değişkenleri Üzerinden

{{#include ../../../banners/hacktricks-training.md}}

Bu runtime'a özgü teknikler, amaçlanan iş yükü başlamadan önce başlangıç yapılandırmasını seçmek, kodu önceden yüklemek veya VM flag'leri sağlamak için devralınan ortam değişkenlerini kullanır. Bazı varyantlar dosya tabanlıdır; Lua ve Erlang ayrıca satır içi kod yürütmeyi de destekler.

## PHP başlangıç yapılandırması

### `PHPRC` / `PHP_INI_SCAN_DIR` ve `auto_prepend_file`

PHP CLI ve CGI, her çağrıda yapılandırma dosyalarını okur. `PHPRC`, saldırganın okuyabildiği bir `php.ini` dosyasını seçebilirken `PHP_INI_SCAN_DIR`, ek `.ini` dosyalarının tarandığı dizini başka bir yere yönlendirebilir. `auto_prepend_file` yönergesi, istenen script'ten önce PHP'nin bir dosyayı parse etmesini sağlar; böylece bu birleşim başlangıçta kod yürütülmesine olanak tanır.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```

Bir alternatif, `.ini` dosyası içeren bir dizindir:

```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```

`-n` seçeneği `php.ini` dosyasını yok sayar; açıkça belirtilen güvenilir bir `-c` yolu, `PHPRC` değişkenine önceliklidir. Uzun süre çalışan bir sunucu SAPI'sinin yapılandırmayı normalde web sunucusu başlatıldığında, CLI ve CGI'nin ise her çağrıda okuduğunu unutmayın.<sup>[[1]](#references)</sup>

## Lua başlangıç kodu

### `LUA_INIT`

Bağımsız Lua yorumlayıcısı, komut satırı seçeneklerini veya hedef betiği işlemeden önce `LUA_INIT_<major>_<minor>` değişkenini ya da sürüme özel değişken tanımlı değilse `LUA_INIT` değişkenini çalıştırır. `@` ile başlayan bir değer bir dosyayı belirtir; diğer tüm değerler doğrudan Lua kodu olarak değerlendirilir. Bu, hem dosyadan hem de dosya olmadan başlangıçta kod çalıştırmayı mümkün kılar.<sup>[[3]](#references)</sup>

```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```

Yorumlayıcının sürüme özgü adı değişir; örneğin `LUA_INIT_5_4`. `lua -E`, başlangıç kodu ve Lua modül yolları dahil tüm ortam değişkenlerini yok sayar.

## Julia başlangıç deposu

### `JULIA_DEPOT_PATH` ve `startup.jl`

Julia, başlangıçta genellikle ilk deposundaki `config/startup.jl` dosyasını çalıştırır. `JULIA_DEPOT_PATH` depo listesini denetler; bu nedenle onu saldırganın okuyabildiği bir ağaç dizinine yönlendirmek, otomatik olarak yüklenen başlangıç dosyasını değiştirir.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```

Son ayırıcı, kurbanın normal paketlerine hâlâ ihtiyaç duyduğu durumlarda kullanışlıdır. `julia --startup-file=no`, bu başlangıç dosyasını devre dışı bırakır. Başlatmadan önce değişkeni temizleyin; çünkü bu değişken paket kayıtlarını, ortamları, önbellekleri ve kod yükleme konumlarını da denetler.

## GNU Octave başlangıç dosyaları

### `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave, başlangıç sırasında geçerli Octave komutları içeren birkaç dosyayı çalıştırır. `OCTAVE_SITE_INITFILE`, site genelindeki başlangıç dosyasını; `OCTAVE_VERSION_INITFILE` ise sürüme özgü başlangıç dosyasını geçersiz kılar. Böylece her iki değişken de otomatik yürütmeyi saldırganın okuyabildiği bir dosyaya yönlendirebilir.<sup>[[6]](#references)</sup>

```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```

`--no-init-file` yalnızca `~/.octaverc` gibi kullanıcı dosyalarını atlar; yukarıdaki site-file geçersiz kılmasını **engellemez**. Site dosyaları için `--no-site-file`, tüm başlangıç dosyalarını devre dışı bırakmak içinse `--norc` / `-f` kullanın.<sup>[[7]](#references)</sup>

## R başlangıç profilleri ve paket yükleme

### `R_PROFILE_USER` / `R_PROFILE`

Başlangıçta R, R kodu içeren site ve kullanıcı profil dosyalarını kaynak olarak çalıştırır. `R_PROFILE` site profilini, `R_PROFILE_USER` ise kullanıcı profilini seçer; böylece devralınan bir ortam, bu aramalardan herhangi birini saldırganın okuyabildiği bir dosyaya yönlendirebilir.<sup>[[8]](#references)</sup>

```bash
echo 'file.create("/tmp/r-profile-executed")' >/tmp/attacker.Rprofile
R_PROFILE_USER=/tmp/attacker.Rprofile Rscript victim.R
```

`--no-init-file` kullanıcı profilini, `--no-site-file` site profilini atlar; `--vanilla` ise her iki korumayı da içerir. R önce `R_ENVIRON` ve `R_ENVIRON_USER` tarafından seçilen ortam dosyalarını işler, ancak bu dosyalar yalnızca değişkenleri ayarlar; profil değişkenleri doğrudan keyfi kod çalıştırma olanağı sağlar.

### `R_DEFAULT_PACKAGES` / `R_SCRIPT_DEFAULT_PACKAGES` ve library paths

R, başlangıç sırasında `R_DEFAULT_PACKAGES` içindeki virgülle ayrılmış paketleri attach eder. `Rscript`, `R_SCRIPT_DEFAULT_PACKAGES` değişkenine öncelik verir. Bu değişkenlerden herhangi birini `R_LIBS`, `R_LIBS_USER` veya `R_LIBS_SITE` ile birlikte kullanmak, R'nin saldırganın kontrolündeki bir kurulu paketi bulup yüklemesine neden olabilir; paketin `.onLoad` veya `.onAttach` hook'u otomatik olarak çalışır.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Assume an installed package named htpayload exists below /tmp/r-library.
R_LIBS_USER=/tmp/r-library \
R_DEFAULT_PACKAGES=htpayload \
R --no-save --no-restore --silent

R_LIBS_USER=/tmp/r-library \
R_SCRIPT_DEFAULT_PACKAGES=htpayload \
Rscript victim.R
```

Bunun için yalnızca bağımsız bir `.R` dosyası değil, yapısal olarak geçerli ve kurulu bir R paketi gerekir. `--vanilla`, doğrudan devralınan değişkenleri temizlemez; bu nedenle güvenilir bir wrapper, profil dosyalarını devre dışı bırakmanın yanı sıra varsayılan paket ve kütüphane yolu değişkenlerini de kaldırmalı veya değiştirmelidir.

## Ruby yükleyici seçenekleri

### RUBYOPT

Ruby, bir scripti çalıştırmadan önce `RUBYOPT` ortam değişkenindeki desteklenen komut satırı anahtarlarını ayrıştırır. Ruby, `RUBYOPT` içinde `-e` ile kod yürütülmesini reddeder; ancak `-I` ile kütüphane arama dizini başa eklenebilir ve `-r` ile bir kütüphane yüklenebilir. Bu nedenle, Ruby’yi saldırganın denetimindeki ortam değişkenleriyle başlatan bir süreç, saldırganın denetimindeki Ruby kodunu yükleyecek şekilde yönlendirilebilir.<sup>[[10]](#references)</sup>

`/tmp/inject.rb` dosyasını oluşturun:

```ruby:inject.rb
puts `whoami`
```

Zararsız bir Ruby betiği oluşturun; örneğin `hello.rb`:

```ruby:hello.rb
puts 'Hello, World!'
```

Kontrollü bir `RUBYOPT` değeriyle çalıştırın:

```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```

Bu davranışı devre dışı bırakmak için `--disable=rubyopt` (veya `--disable-rubyopt`) seçeneğini betik adından **önce** belirtin:<sup>[[10]](#references)</sup>

```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```

`hello.rb`'den sonra yazılan bir seçenek, `ARGV` içinde betiğe aktarılır; Ruby'nin `RUBYOPT`'u daha önce işlemesini devre dışı bırakmaz.<sup>[[10]](#references)</sup>

```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```

### RUBYLIB

`RUBYOPT` içinde `-I` ile yükleme dizinini başa eklemek yerine, ayrı `RUBYLIB` ortam değişkeni Ruby'nin `$LOAD_PATH`'ine dizinler ekler. `RUBYOPT=-r<module>` ile birlikte kullanıldığında, `RUBYOPT` içinde `-I` kullanmaya gerek kalmadan saldırgan kodu yükler:<sup>[[10]](#references)</sup>

```bash
echo "puts \`whoami\`" > /tmp/inject.rb
RUBYLIB=/tmp RUBYOPT=-rinject ruby hello.rb
```

## Erlang ve Elixir VM bayrakları

### `ERL_AFLAGS`, `ERL_FLAGS` ve `ERL_ZFLAGS`

`erl` başlatıcısı, `ERL_AFLAGS` değişkenini komut satırının başına, `ERL_FLAGS` / `ERL_ZFLAGS` değişkenlerini ise sonuna ekler. `-eval`, VM başlatılırken bir Erlang ifadesini değerlendirdiğinden, bu değişkenler amaçlanan iş yükü başlamadan önce dosyasız kod yürütülmesini sağlayabilir.<sup>[[11]](#references)</sup>

```bash
ERL_AFLAGS="-noshell -eval 'file:write_file(\"/tmp/erl-aflags-executed\", <<\"ok\">>).' -s init stop" erl
```

Elixir, Mix, Phoenix ve birçok Elixir sürümü nihayetinde Erlang VM'yi başlatır ve bu flag'leri devralabilir. Tam release wrapper'ını doğrulayın: VM argümanlarını yeniden oluşturabilir veya temizleyebilir; bazı araçlar ise `ERL_AFLAGS`, `ERL_ZFLAGS` ya da `ELIXIR_ERL_OPTIONS` değişkenlerini açıkça destekler.<sup>[[12]](#references)</sup>

Dosya tabanlı tekniklerin çoğundan farklı olarak, `-eval` payload'ı saldırganın kontrolündeki bir dosyaya ihtiyaç duymaz. Güvenilir bir wrapper, runtime'ı başlatmadan önce üç Erlang flag değişkenini de (Elixir için `ELIXIR_ERL_OPTIONS` değişkenini de) temizlemelidir; parser ve sıralama tam olarak anlaşılmadığı sürece tek tek VM flag'lerine izin vermeye çalışmayın.

## References

- [1] [PHP yapılandırma dosyası](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
- [3] [Lua 5.4 bağımsız yorumlayıcısı](https://www.lua.org/manual/5.4/manual.html#7)
- [4] [Julia komut satırı arayüzü: Başlangıç dosyası](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [5] [Julia ortam değişkenleri: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
- [6] [GNU Octave başlangıç dosyaları](https://docs.octave.org/latest/Startup-Files.html)
- [7] [GNU Octave komut satırı seçenekleri](https://docs.octave.org/latest/Command-Line-Options.html)
- [8] [R oturumunun başlangıcında başlatma](https://stat.ethz.ch/R-manual/R-devel/library/base/html/Startup.html)
- [9] [R kurulumu ve yönetimi: Eklenti paketleri](https://stat.ethz.ch/CRAN/doc/manuals/r-release/R-admin.html)
- [10] [Ruby belgeleri - Ruby komut satırı seçenekleri](https://ruby-doc.org/3.4/ruby/options_md.html)
- [11] [`erl` komutu ve ortam değişkenleri](https://www.erlang.org/doc/apps/erts/erl_cmd.html)
- [12] [Elixir release'leri ve VM ortam seçenekleri](https://hexdocs.pm/elixir/releases.html#operating-system-scripts)
{{#include ../../../banners/hacktricks-training.md}}
