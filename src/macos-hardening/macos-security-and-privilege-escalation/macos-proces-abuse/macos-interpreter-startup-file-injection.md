# macOS Interpreter Startup-File Injection

{{#include ../../../banners/hacktricks-training.md}}

Mbinu hizi maalum kwa runtime hutumia environment variables zilizorithiwa kuchagua startup configuration au code kabla ya script iliyokusudiwa. Lua pia inaruhusu variant ya inline-code.

## PHP startup configuration

### `PHPRC` / `PHP_INI_SCAN_DIR` na `auto_prepend_file`

PHP CLI na CGI husoma configuration kila zinapoendeshwa. `PHPRC` inaweza kuchagua `php.ini` ambayo mshambuliaji anaweza kuisoma, huku `PHP_INI_SCAN_DIR` ikielekeza upya directory inayochunguzwa kwa ajili ya faili za ziada za `.ini`. Directive ya `auto_prepend_file` husababisha PHP kuchanganua faili kabla ya script iliyoombwa, kwa hivyo mchanganyiko huu huwezesha code execution wakati wa startup.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```

Njia mbadala ni saraka iliyo na faili ya `.ini`:

```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```

Chaguo la `-n` hupuuza `php.ini`; njia inayoaminika iliyoainishwa wazi kwa `-c` hutangulia `PHPRC`. Kumbuka kuwa SAPI ya seva inayoendelea kufanya kazi kwa kawaida husoma usanidi seva ya wavuti inapoanza, ilhali CLI na CGI husoma usanidi kila zinapoendeshwa.<sup>[[1]](#references)</sup>

## Msimbo wa kuanzisha Lua

### `LUA_INIT`

Kabla ya kuchakata chaguo za mstari wa amri au script lengwa, mkalimani huru wa Lua huendesha `LUA_INIT_<major>_<minor>` au, ikiwa kigezo chenye toleo hilo hakipo, `LUA_INIT`. Thamani inayoanza na `@` hubainisha faili; thamani nyingine yoyote hutathminiwa moja kwa moja kama msimbo wa Lua. Hii huruhusu utekelezaji wa kuanzisha kupitia faili au bila faili.<sup>[[3]](#references)</sup>

```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```

Jina halisi lenye toleo hubadilika kulingana na interpreter, kwa mfano `LUA_INIT_5_4`. `lua -E` hupuuza vigeu vyote vya mazingira, ikiwemo startup code na njia za Lua module.

## Depot ya startup ya Julia

### `JULIA_DEPOT_PATH` na `startup.jl`

Kwa kawaida, Julia huendesha `config/startup.jl` kutoka depot yake ya kwanza inapoanza. `JULIA_DEPOT_PATH` hudhibiti orodha ya depot, kwa hivyo kuielekeza kwenye mti unaoweza kusomwa na attacker huelekeza upya faili ya startup inayopakiwa kiotomatiki.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```

Kitenganishi cha mwisho ni muhimu ikiwa mwathiriwa bado anahitaji vifurushi vyake vya kawaida. `julia --startup-file=no` huzima faili hii ya startup. Futa kigezo kabla ya kuzindua programu kwa sababu pia hudhibiti sajili za vifurushi, mazingira, akiba na maeneo ya kupakia msimbo.

## Faili za startup za GNU Octave

### `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave hutekeleza faili kadhaa zenye amri halali za Octave wakati wa startup. `OCTAVE_SITE_INITFILE` hubatilisha faili ya startup ya tovuti nzima, na `OCTAVE_VERSION_INITFILE` hubatilisha faili mahususi ya toleo, hivyo kuruhusu mojawapo ya vigezo hivyo kuelekeza utekelezaji wa kiotomatiki kwenye faili ambayo mshambulizi anaweza kuandika.<sup>[[6]](#references)</sup>

```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```

`--no-init-file` huruka tu faili za mtumiaji kama `~/.octaverc`; **haizuii** ubadilishaji wa faili ya site ulioelezwa hapo juu. Tumia `--no-site-file` kwa faili za site au `--norc` / `-f` kuzima faili zote za startup.<sup>[[7]](#references)</sup>

## References

- [1] [Faili ya usanidi ya PHP](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
- [3] [Interpreter ya kujitegemea ya Lua 5.4](https://www.lua.org/manual/5.4/manual.html#7)
- [4] [Kiolesura cha mstari wa amri cha Julia: Faili ya startup](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [5] [Vigezo vya mazingira vya Julia: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
- [6] [Faili za startup za GNU Octave](https://docs.octave.org/latest/Startup-Files.html)
- [7] [Chaguo za mstari wa amri za GNU Octave](https://docs.octave.org/latest/Command-Line-Options.html)
{{#include ../../../banners/hacktricks-training.md}}
