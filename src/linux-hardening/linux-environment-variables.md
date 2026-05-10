# Variáveis de Ambiente do Linux

{{#include ../banners/hacktricks-training.md}}

## Variáveis globais

As variáveis globais **serão** herdadas pelos **processos filhos**.

Você pode criar uma variável global para sua sessão atual fazendo:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Esta variável estará acessível pelas suas sessões atuais e pelos seus processos filhos.

Você pode **remover** uma variável fazendo:
```bash
unset MYGLOBAL
```
## Variáveis locais

As **variáveis locais** só podem ser **acessadas** pelo **shell/script atual**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Listar variáveis atuais
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
Os conteúdos de `/proc/*/environ` são **separados por NUL**, então estas variantes costumam ser mais fáceis de ler:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Se você estiver procurando por **credentials** ou **interesting service configuration** dentro de ambientes herdados, também verifique [Linux Post Exploitation](linux-post-exploitation/README.md).

## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – o display usado pelo **X**. Essa variável normalmente é definida como **:0.0**, o que significa o primeiro display no computador atual.
- **EDITOR** – o editor de texto preferido do usuário.
- **HISTFILESIZE** – o número máximo de linhas contidas no arquivo de history.
- **HISTSIZE** – número de linhas adicionadas ao arquivo de history quando o usuário termina sua sessão
- **HOME** – seu diretório home.
- **HOSTNAME** – o hostname do computador.
- **LANG** – seu idioma atual.
- **MAIL** – o local do spool de mail do usuário. Normalmente **/var/spool/mail/USER**.
- **MANPATH** – a lista de diretórios a serem pesquisados para páginas de manual.
- **OSTYPE** – o tipo de sistema operacional.
- **PS1** – o prompt padrão no bash.
- **PATH** – armazena o path de todos os diretórios que contêm arquivos binários que você deseja executar apenas especificando o nome do arquivo e não por path relativo ou absoluto.
- **PWD** – o diretório de trabalho atual.
- **SHELL** – o path para o shell de comandos atual (por exemplo, **/bin/bash**).
- **TERM** – o tipo de terminal atual (por exemplo, **xterm**).
- **TZ** – seu fuso horário.
- **USER** – seu nome de usuário atual.

## Interesting variables for hacking

Nem toda variável é igualmente útil. De uma perspectiva ofensiva, priorize variáveis que alteram **search paths**, **startup files**, **dynamic linker behavior**, ou **audit/logging**.

### **HISTFILESIZE**

Altere o **valor desta variável para 0**, assim quando você **encerrar sua sessão** o **history file** (\~/.bash_history) será **truncated to 0 lines**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Altere o **valor desta variável para 0**, para que os comandos **não sejam mantidos no histórico em memória** e não sejam gravados de volta no **arquivo de histórico** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Se o **valor desta variável estiver definido como `ignorespace` ou `ignoreboth`**, qualquer comando precedido por um espaço extra não será salvo no histórico.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

Aponte o **arquivo de histórico** para **`/dev/null`** ou desative-o completamente. Isso geralmente é mais confiável do que apenas alterar o tamanho do histórico.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Os processos usarão o **proxy** declarado aqui para se conectar à internet por **http ou https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: proxy padrão para ferramentas/protocolos que o respeitam.
- `no_proxy`: lista de bypass (hosts/domínios/CIDRs) que deve conectar diretamente.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
Tanto variantes em minúsculas quanto em maiúsculas podem ser usadas dependendo da ferramenta (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Os processos confiarão nos certificados indicados em **essas env variables**. Isso é útil para fazer ferramentas como **`curl`**, **`git`**, clientes HTTP em Python, ou gerenciadores de pacotes confiarem em uma CA controlada pelo atacante (por exemplo, para fazer um proxy de interceptação parecer legítimo).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Se um wrapper/script privilegiado executa comandos **sem caminhos absolutos**, o **primeiro diretório controlado pelo atacante** em `PATH` vence. Este é o primitive por trás de muitos **PATH hijacks** em `sudo`, cron jobs, shell wrappers e helpers SUID personalizados. Procure por `env_keep+=PATH`, `secure_path` fraco, ou wrappers que chamam `tar`, `service`, `cp`, `python`, etc. pelo nome.
```bash
mkdir -p /dev/shm/bin
cat > /dev/shm/bin/tar <<'EOF'
#!/bin/sh
echo '[+] PATH hijack reached' >&2
id
EOF
chmod +x /dev/shm/bin/tar
PATH=/dev/shm/bin:$PATH vulnerable-wrapper
```
Para cadeias completas de privilege-escalation abusando de `PATH`, consulte [Linux Privilege Escalation](privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` não é apenas uma referência de diretório: muitas ferramentas carregam automaticamente **dotfiles**, **plugins** e **configuração por usuário** a partir de `$HOME` ou `$XDG_CONFIG_HOME`. Se um fluxo privilegiado preserva esses valores, **config injection** pode ser mais fácil do que binary hijacking.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Alvos interessantes incluem `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` e arquivos específicos de ferramentas como `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Essas variáveis influenciam o **dynamic linker**:

- `LD_PRELOAD`: força objetos compartilhados extras a serem carregados primeiro.
- `LD_LIBRARY_PATH`: adiciona diretórios de busca de libraries no início.
- `LD_AUDIT`: carrega libraries auditoras que observam o carregamento de libraries e a resolução de símbolos.

Elas são extremamente valiosas para **hooking**, **instrumentation** e **privilege escalation** se um comando privilegiado as preservar. No modo de **secure-execution** (`AT_SECURE`, por exemplo, setuid/setgid/capabilities), o loader remove ou restringe muitas dessas variáveis. No entanto, bugs de parser nessa fase inicial do loader ainda têm alto impacto, porque executam **before** o target program.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` altera o comportamento inicial do glibc (por exemplo, tunables do allocator) e é muito útil em labs de exploit. Também importa do ponto de vista de segurança porque o **dynamic loader o analisa muito cedo**. O bug **Looney Tunables** de 2023 foi um bom lembrete de que uma única environment variable analisada no loader pode se tornar um **local privilege-escalation primitive** contra programas SUID.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Se **Bash** for iniciado **non-interactively**, ele verifica `BASH_ENV` e faz source desse arquivo antes de executar o script alvo. Quando Bash é invocado como `sh`, ou em modo interativo estilo POSIX, `ENV` também pode ser consultado. Essa é uma forma clássica de transformar um shell wrapper em execução de código se o ambiente estiver sob controle do atacante.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
O próprio Bash desabilita esses arquivos de inicialização quando os **IDs reais/efetivos diferem** a menos que `-p` seja usado, então o comportamento exato depende de como o wrapper invoca o shell.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Essas variáveis alteram como o Python inicia:

- `PYTHONPATH`: adiciona paths de busca de import no início.
- `PYTHONHOME`: realoca a árvore da biblioteca padrão.
- `PYTHONSTARTUP`: executa um arquivo antes do prompt interativo.
- `PYTHONINSPECT=1`: entra em modo interativo após um script terminar.

Elas são úteis contra scripts de manutenção, debuggers, shells e wrappers que chamam Python com um ambiente controlável. `python -E` e `python -I` ignoram todas as variáveis `PYTHON*`.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
### **PERL5OPT & PERL5LIB**

Perl tem variáveis de inicialização igualmente úteis:

- `PERL5LIB`: adiciona diretórios de bibliotecas no início.
- `PERL5OPT`: injeta switches como se estivessem em cada linha de comando do `perl`.

Isso pode forçar **automatic module loading** ou alterar o comportamento do interpretador antes que o script alvo faça qualquer coisa interessante. Perl ignora essas variáveis em contextos de **taint / setuid / setgid**, mas elas ainda importam muito para wrappers normais executados como root, jobs de CI, installers e regras customizadas de sudoers.
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
A mesma ideia aparece em outros runtimes (`RUBYOPT`, `NODE_OPTIONS`, etc.): sempre que um interpretador é iniciado por um wrapper privilegiado, procure por env vars que modificam **module loading** ou **startup behavior**.

Da perspectiva de post-exploitation, também lembre que ambientes herdados frequentemente contêm **credentials**, **proxy settings**, **service tokens** ou **cloud keys**. Confira [Linux Post Exploitation](linux-post-exploitation/README.md) para caça em `/proc/<PID>/environ` e `systemd` `Environment=`.

### PS1

Altere como seu prompt aparece.

[**Este é um exemplo**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../images/image (897).png>)

Usuário regular:

![](<../images/image (740).png>)

Uma, duas e três jobs em background:

![](<../images/image (145).png>)

Uma job em background, uma parada e o último comando não terminou corretamente:

![](<../images/image (715).png>)

## References

- [GNU Bash Manual - Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)

{{#include ../banners/hacktricks-training.md}}
