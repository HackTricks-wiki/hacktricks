# Injeção em Aplicações Shell do macOS

{{#include ../../../banners/hacktricks-training.md}}

## `BASH_ENV`

Quando o Bash é iniciado de forma não interativa para executar um script ou um comando `-c`, ele expande o valor de `BASH_ENV` e obtém o arquivo resultante antes de executar o comando solicitado. O Bash não usa `PATH` para localizar esse arquivo. Portanto, um processo que inicia o Bash não interativo com variáveis de ambiente controladas pelo atacante pode ser induzido a executar primeiro um payload de shell legível.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/bash-startup-hook.sh <<'EOF'
#!/bin/bash
/usr/bin/touch /tmp/bash-env-executed
EOF

BASH_ENV=/tmp/bash-startup-hook.sh /bin/bash -c '/usr/bin/true'
test -e /tmp/bash-env-executed && echo 'BASH_ENV executed'
```
O hook é executado somente quando o alvo realmente inicia o Bash; `/bin/sh` em outra plataforma ou um programa que executa um comando sem um shell não necessariamente o respeitará. O Bash em modo privilegiado ignora `BASH_ENV`. Quando os IDs efetivo e real de usuário/grupo são diferentes, o Bash também ignora os arquivos de inicialização e redefine os IDs efetivos, a menos que `-p` seja fornecido; com `-p`, o modo privilegiado permanece habilitado e `BASH_ENV` continua sendo ignorado.<sup>[[1]](#references)[[2]](#references)</sup>

No macOS, os jobs do `launchd` podem definir variáveis de ambiente herdadas ou específicas por job; portanto, inspecione os plists e os contextos de inicialização que alimentam scripts privilegiados. Não dependa apenas do SIP para limpar as variáveis do interpretador: use um ambiente mínimo (`env -i`), remova explicitamente `BASH_ENV`, invoque o interpretador pretendido usando seu caminho absoluto e evite arquivos de inicialização graváveis.

## zsh `ZDOTDIR`

O zsh lê `$ZDOTDIR/.zshenv` para todo shell normal, incluindo shells não interativos; se `ZDOTDIR` não estiver definido, ele usa `HOME`. Redirecionar `ZDOTDIR` para um diretório gravável, portanto, executa seu `.zshenv` antes de um comando ou script `zsh -c`.<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/zsh-startup
echo '/usr/bin/touch /tmp/zshenv-executed' > /tmp/zsh-startup/.zshenv
ZDOTDIR=/tmp/zsh-startup /bin/zsh -c /usr/bin/true
```
`zsh -f` desativa a opção `RCS` e ignora este arquivo de inicialização do usuário. O `/etc/zshenv` global ainda é lido, portanto deve permanecer confiável e minimalista.

## fish `XDG_CONFIG_HOME`

fish lê `$XDG_CONFIG_HOME/fish/conf.d/*.fish` e `$XDG_CONFIG_HOME/fish/config.fish` na inicialização de cada shell, não apenas de shells interativos ou de login. Ele também executa `fish/vendor_conf.d/*.fish` abaixo das entradas em `XDG_DATA_DIRS`. Portanto, um atacante que controle uma dessas variáveis e um diretório legível pode executar código antes de um script fish ou de um comando `-c`.<sup>[[4]](#references)</sup>
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

## References

- [1] [Arquivos de inicialização do Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
- [2] [Invocando o Bash](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [3] [Arquivos de inicialização/desligamento do zsh](https://zsh.sourceforge.io/Doc/Release/Files.html#Startup_002fShutdown-Files)
- [4] [Arquivos de configuração do fish](https://fishshell.com/docs/current/language.html#configuration-files)
{{#include ../../../banners/hacktricks-training.md}}
