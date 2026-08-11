# Variáveis de ambiente do Linux

## Variáveis globais

As variáveis globais **serão** herdadas pelos **processos filhos**.

Você pode criar uma variável global para sua sessão atual executando:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Esta variável estará acessível pelas suas sessões atuais e pelos processos filhos delas.

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
O conteúdo de `/proc/*/environ` é **separado por NUL**, portanto estas variantes geralmente são mais fáceis de ler:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Se você estiver procurando por **credenciais** ou **configuração interessante de serviços** dentro de ambientes herdados, verifique também [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md).

## Variáveis comuns

De: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – o display usado pelo **X**. Essa variável geralmente é definida como **:0.0**, o que significa o primeiro display no computador atual.
- **EDITOR** – o editor de texto preferido do usuário.
- **HISTFILESIZE** – o número máximo de linhas contidas no arquivo de histórico.
- **HISTSIZE** – número de linhas adicionadas ao arquivo de histórico quando o usuário encerra sua sessão.
- **HOME** – seu diretório inicial.
- **HOSTNAME** – o hostname do computador.
- **LANG** – seu idioma atual.
- **MAIL** – o local do spool de e-mail do usuário. Geralmente **/var/spool/mail/USER**.
- **MANPATH** – a lista de diretórios a serem pesquisados para encontrar páginas de manual.
- **OSTYPE** – o tipo de sistema operacional.
- **PS1** – o prompt padrão no bash.
- **PATH** – armazena o caminho de todos os diretórios que contêm arquivos binários que você deseja executar especificando apenas o nome do arquivo, e não o caminho relativo ou absoluto.
- **PWD** – o diretório de trabalho atual.
- **SHELL** – o caminho para o shell de comandos atual (por exemplo, **/bin/bash**).
- **TERM** – o tipo de terminal atual (por exemplo, **xterm**).
- **TZ** – seu fuso horário.
- **USER** – seu nome de usuário atual.

## Variáveis interessantes para hacking

Nem todas as variáveis são igualmente úteis. De uma perspectiva ofensiva, priorize as variáveis que alteram **caminhos de pesquisa**, **arquivos de inicialização**, **comportamento do dynamic linker** ou **auditoria/logging**.

### **HISTFILESIZE**

Altere o **valor desta variável para 0** para que, quando você **encerrar sua sessão**, o **arquivo de histórico** (\~/.bash_history) seja **truncado para 0 linhas**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Altere o **valor desta variável para 0**, para que os comandos **não sejam mantidos no histórico em memória** e não sejam gravados no **arquivo de histórico** (\~/.bash_history).
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

Se o **valor desta variável estiver definido como `ignorespace` ou `ignoreboth`**, qualquer comando precedido por um espaço adicional não será salvo no histórico.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

Aponte o **arquivo de histórico** para **`/dev/null`** ou desconfigure-o completamente. Isso geralmente é mais confiável do que apenas alterar o tamanho do histórico.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Os processos usarão o **proxy** declarado aqui para se conectar à internet por meio de **http ou https**.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: proxy padrão para ferramentas/protocolos que o suportam.
- `no_proxy`: lista de bypass (hosts/domínios/CIDRs) que devem se conectar diretamente.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
As variantes em minúsculas e maiúsculas podem ser usadas dependendo da ferramenta (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Os processos confiarão nos certificados indicados **nessas variáveis de ambiente**. Isso é útil para fazer com que ferramentas como **`curl`**, **`git`**, clientes HTTP do Python ou gerenciadores de pacotes confiem em uma CA controlada pelo atacante (por exemplo, para fazer com que um proxy de interceptação pareça legítimo).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Se um wrapper/script privilegiado executar comandos **sem caminhos absolutos**, o **primeiro diretório controlado pelo atacante** em `PATH` vence. Esse é o primitivo por trás de muitos **PATH hijacks** em `sudo`, jobs do cron, shell wrappers e helpers SUID personalizados. Procure por `env_keep+=PATH`, `secure_path` fraco ou wrappers que chamem `tar`, `service`, `cp`, `python` etc. pelo nome.
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
Para obter cadeias completas de privilege escalation abusando de `PATH`, consulte [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` não é apenas uma referência de diretório: muitas ferramentas carregam automaticamente **dotfiles**, **plugins** e **configurações por usuário** de `$HOME` ou `$XDG_CONFIG_HOME`. Se um workflow privilegiado preservar esses valores, a **config injection** poderá ser mais fácil do que o **binary hijacking**.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Alvos interessantes incluem `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` e arquivos específicos de ferramentas, como `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Essas variáveis influenciam o **dynamic linker**:

- `LD_PRELOAD`: força o carregamento antecipado de objetos compartilhados adicionais.
- `LD_LIBRARY_PATH`: antepõe diretórios de busca de bibliotecas.
- `LD_AUDIT`: carrega bibliotecas auditoras que observam o carregamento de bibliotecas e a resolução de símbolos.

Elas são extremamente valiosas para **hooking**, **instrumentation** e **privilege escalation** quando um comando privilegiado as preserva. No modo de **secure-execution** (`AT_SECURE`, por exemplo, setuid/setgid/capabilities), o loader remove ou restringe muitas dessas variáveis. No entanto, parser bugs nessa etapa inicial do loader ainda têm alto impacto porque são executados **antes** do programa-alvo.<sup>[[2]](#references)</sup>
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` altera o comportamento inicial da glibc (por exemplo, os tunables do allocator) e é muito útil em labs de exploit. Também é relevante do ponto de vista de segurança porque o **dynamic loader faz o parsing dela muito cedo**. O bug **Looney Tunables** de 2023 foi um bom lembrete de que uma única environment variable analisada pelo loader pode se tornar uma **primitive de local privilege escalation** contra programas SUID.<sup>[[6]](#references)</sup>
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Se o **Bash** for iniciado **não interativamente**, ele verifica `BASH_ENV` e carrega esse arquivo antes de executar o script alvo. Quando o Bash é invocado como `sh` ou no modo interativo no estilo POSIX, `ENV` também pode ser consultado. Essa é uma forma clássica de transformar um wrapper de shell em execução de código quando o ambiente é controlado pelo atacante.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
O Bash ignora esses arquivos de inicialização quando os **IDs real/efetivo são diferentes**; `-p` preserva o ID efetivo, mas não habilita esses arquivos de inicialização, portanto o comportamento exato depende de como o wrapper inicia o shell. Tenha cuidado com wrappers privilegiados que chamam `setuid()`/`setgid()` **antes** de iniciar o Bash: quando os IDs voltam a corresponder, o Bash pode confiar em `BASH_ENV`, `ENV` e no estado relacionado do shell, que de outra forma seriam ignorados.<sup>[[1]](#references)</sup>

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Essas variáveis alteram a forma como o Python é iniciado:

- `PYTHONPATH`: adiciona caminhos de busca de importação no início.
- `PYTHONHOME`: realoca a árvore da biblioteca padrão.
- `PYTHONSTARTUP`: executa um arquivo antes do prompt interativo.
- `PYTHONINSPECT=1`: entra no modo interativo após a conclusão de um script.

Elas são úteis contra scripts de manutenção, debuggers, shells e wrappers que chamam o Python com um ambiente controlável. `python -E` e `python -I` ignoram todas as variáveis `PYTHON*`.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
Um exemplo recente do mundo real foi o LPE do **needrestart** em 2024, em sistemas Ubuntu/Debian: o scanner pertencente ao root copiava o `PYTHONPATH` de um processo sem privilégios a partir de `/proc/<PID>/environ` e, em seguida, executava Python. O exploit publicado colocou `importlib/__init__.so` no caminho controlado pelo atacante, fazendo com que o Python executasse o código do atacante durante sua própria inicialização, antes mesmo que o script definido diretamente no helper tivesse importância.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

O Perl possui variáveis de inicialização igualmente úteis:

- `PERL5LIB`: adiciona diretórios de bibliotecas ao início do caminho.
- `PERL5OPT`: injeta switches como se estivessem na linha de comando de todo `perl`.

Isso pode forçar o **carregamento automático de módulos** ou alterar o comportamento do interpretador antes que o script-alvo faça algo interessante. O Perl ignora essas variáveis em contextos de **taint / setuid / setgid**, mas elas ainda são muito relevantes para wrappers normais executados como root, jobs de CI, instaladores e regras personalizadas do sudoers.
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
### **NODE_OPTIONS**

`NODE_OPTIONS` adiciona **flags da CLI do Node.js** ao início de cada processo `node` que herda o ambiente. Isso o torna útil contra wrappers, jobs de CI, auxiliares do Electron e regras do sudo que eventualmente executam o Node. As flags mais interessantes ofensivamente geralmente são:

- `--require <file>`: pré-carrega um arquivo CommonJS antes do script-alvo.
- `--import <module>`: pré-carrega um módulo ES antes do script-alvo.

O Node rejeita algumas flags perigosas em `NODE_OPTIONS`, mas `--require` e `--import` são explicitamente permitidas e processadas **antes** dos argumentos regulares da linha de comando.<sup>[[4]](#references)</sup>
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
Para cadeias de gadgets remotas que definem `NODE_OPTIONS` indiretamente (por exemplo, de prototype-pollution para RCE), consulte [esta outra página](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby oferece a mesma classe de abuso na inicialização:

- `RUBYLIB`: adiciona diretórios ao início do load path do Ruby.
- `RUBYOPT`: injeta opções de linha de comando, como `-r`, em toda invocação de `ruby`.
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
As vulnerabilidades do **needrestart** de 2024 mostraram que isso não é apenas um truque de laboratório: o mesmo helper pertencente ao root que era vulnerável ao abuso de `PYTHONPATH` também poderia ser induzido a executar Ruby com um `RUBYLIB` controlado pelo atacante, carregando `enc/encdb.so` a partir de um diretório controlado pelo atacante.<sup>[[3]](#references)</sup>

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Algumas ferramentas não apenas leem um caminho do ambiente; elas passam o valor para um **shell**, um **editor** ou um **input preprocessor**. Isso torna as variáveis a seguir especialmente interessantes quando um wrapper privilegiado executa `git`, `man`, `less` ou visualizadores de texto semelhantes:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: escolhem o comando do pager.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: escolhem o comando do editor, geralmente com argumentos.
- `LESSOPEN`, `LESSCLOSE`: definem pré/pós-processadores executados quando `less` abre um arquivo.
```bash
PAGER='sh -c "exec sh 0<&1 1>&1"' man man

cat > /tmp/lesspipe.sh <<'EOF'
#!/bin/sh
echo '[+] LESSOPEN triggered' >&2
cat "$1"
EOF
chmod +x /tmp/lesspipe.sh
LESSOPEN='|/tmp/lesspipe.sh %s' less /etc/hosts
```
O Git também oferece suporte à **injeção de configuração somente por variáveis de ambiente** sem tocar no disco por meio de `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` e `GIT_CONFIG_VALUE_<n>`:
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
De uma perspectiva de post-exploitation, lembre-se também de que ambientes herdados geralmente contêm **credenciais**, **configurações de proxy**, **service tokens** ou **cloud keys**. Consulte [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) para procurar por `/proc/<PID>/environ` e `systemd` `Environment=`.

### PS1

Altere a aparência do seu prompt.

[**Este é um exemplo**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Este é um exemplo](<../images/image (897).png>)

Usuário comum:

![PERL5OPT & PERL5LIB - PS1: Um, dois e três jobs em background](<../images/image (740).png>)

Um, dois e três jobs em background:

![PERL5OPT & PERL5LIB - PS1: Um, dois e três jobs em background](<../images/image (145).png>)

Um job em background, um parado e o último comando não foi concluído corretamente:

![PERL5OPT & PERL5LIB - PS1: Um job em background, um parado e o último comando não foi concluído corretamente](<../images/image (715).png>)

## References

- [1] [Manual do GNU Bash - Arquivos de inicialização do Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Página do manual do Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPEs no needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Documentação da CLI do Node.js - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Variáveis de ambiente comuns - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - Escalonamento local de privilégios no ld.so da glibc - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
{{#include ../../banners/hacktricks-training.md}}
