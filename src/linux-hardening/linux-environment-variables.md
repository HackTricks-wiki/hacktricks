# Variáveis de Ambiente do Linux

{{#include ../banners/hacktricks-training.md}}

## Variáveis globais

As variáveis globais **serão** herdadas por **processos filhos**.

Você pode criar uma variável global para sua sessão atual fazendo:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Esta variável será acessível pelas suas sessões atuais e seus processos filhos.

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
O conteúdo de `/proc/*/environ` é **separado por NUL**, então estas variantes geralmente são mais fáceis de ler:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
Se você estiver procurando por **credentials** ou por **interesting service configuration** em ambientes herdados, também verifique [Linux Post Exploitation](linux-post-exploitation/README.md).

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
- **MANPATH** – a lista de diretórios a ser pesquisada para páginas de manual.
- **OSTYPE** – o tipo de sistema operacional.
- **PS1** – o prompt padrão no bash.
- **PATH** – armazena o path de todos os diretórios que contêm arquivos binários que você deseja executar apenas especificando o nome do arquivo e não por path relativo ou absoluto.
- **PWD** – o diretório de trabalho atual.
- **SHELL** – o path para o shell de comando atual (por exemplo, **/bin/bash**).
- **TERM** – o tipo de terminal atual (por exemplo, **xterm**).
- **TZ** – seu fuso horário.
- **USER** – seu nome de usuário atual.

## Interesting variables for hacking

Nem toda variável é igualmente útil. De uma perspectiva ofensiva, priorize variáveis que alteram **search paths**, **startup files**, **dynamic linker behavior**, ou **audit/logging**.

### **HISTFILESIZE**

Altere o **valor dessa variável para 0**, assim, quando você **encerrar sua sessão**, o **history file** (\~/.bash_history) será **truncated to 0 lines**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Altere o **valor dessa variável para 0**, para que os comandos **não sejam mantidos no histórico em memória** e não sejam gravados de volta no **arquivo de histórico** (\~/.bash_history).
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

Aponte o **history file** para **`/dev/null`** ou desconfigure-o completamente. Isso geralmente é mais confiável do que apenas alterar o tamanho do histórico.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

Os processos usarão o **proxy** declarado aqui para se conectar à internet por meio de **http or https**.
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

Os processos confiarão nos certificados indicados em **estas variáveis de ambiente**. Isso é útil para fazer ferramentas como **`curl`**, **`git`**, clientes HTTP Python ou gerenciadores de pacotes confiarem em uma CA controlada pelo atacante (por exemplo, para fazer um proxy de interceptação parecer legítimo).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

Se um wrapper/script privilegiado executa comandos **sem caminhos absolutos**, o **primeiro diretório controlado pelo atacante** em `PATH` vence. Este é o primitivo por trás de muitos **PATH hijacks** em `sudo`, cron jobs, shell wrappers e custom SUID helpers. Procure por `env_keep+=PATH`, `secure_path` fraco, ou wrappers que chamem `tar`, `service`, `cp`, `python`, etc. pelo nome.
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
Para cadeias completas de privilege-escalation abusando de `PATH`, confira [Linux Privilege Escalation](privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` não é apenas uma referência de diretório: muitas ferramentas carregam automaticamente **dotfiles**, **plugins** e **configuração por usuário** de `$HOME` ou `$XDG_CONFIG_HOME`. Se um workflow privilegiado preserva esses valores, **config injection** pode ser mais fácil do que binary hijacking.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Interessantes alvos incluem `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` e arquivos específicos de ferramentas, como `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Essas variáveis influenciam o **dynamic linker**:

- `LD_PRELOAD`: força que objetos compartilhados extras sejam carregados primeiro.
- `LD_LIBRARY_PATH`: adiciona diretórios de busca de bibliotecas no início.
- `LD_AUDIT`: carrega bibliotecas auditoras que observam o carregamento de bibliotecas e a resolução de símbolos.

Elas são extremamente valiosas para **hooking**, **instrumentation** e **privilege escalation** se um comando privilegiado preservá-las. No modo de **secure-execution** (`AT_SECURE`, por exemplo setuid/setgid/capabilities), o loader remove ou restringe muitas dessas variáveis. No entanto, bugs de parser nessa fase inicial do loader continuam tendo alto impacto porque executam **antes** do programa alvo.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` altera o comportamento inicial da glibc (por exemplo, tunables do allocator) e é muito útil em laboratórios de exploit. Também importa do ponto de vista de segurança porque o **dynamic loader o analisa muito cedo**. O bug **Looney Tunables** de 2023 foi um bom lembrete de que uma única environment variable analisada no loader pode se tornar um **primitive de local privilege-escalation** contra programas SUID.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

Se o **Bash** for iniciado **não interativamente**, ele verifica `BASH_ENV` e carrega esse arquivo antes de executar o script alvo. Quando o Bash é invocado como `sh`, ou em modo interativo estilo POSIX, `ENV` também pode ser consultado. Esta é uma forma clássica de transformar um wrapper de shell em execução de código se o ambiente estiver sob controle do atacante.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
O próprio Bash desativa esses arquivos de inicialização quando os **IDs reais/efetivos diferem** a menos que `-p` seja usado, então o comportamento exato depende de como o wrapper invoca o shell.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

Essas variáveis mudam como o Python inicia:

- `PYTHONPATH`: adiciona paths de busca de importação no início.
- `PYTHONHOME`: realoca a árvore da biblioteca padrão.
- `PYTHONSTARTUP`: executa um arquivo antes do prompt interativo.
- `PYTHONINSPECT=1`: entra no modo interativo depois que um script termina.

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
- `PERL5OPT`: injeta switches como se estivessem em cada linha de comando `perl`.

Isso pode forçar **automatic module loading** ou alterar o comportamento do interpretador antes que o script alvo faça qualquer coisa interessante. O Perl ignora essas variáveis em contextos **taint / setuid / setgid**, mas elas ainda importam bastante para wrappers normais executados como root, jobs de CI, installers e regras customizadas de sudoers.
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
A mesma ideia aparece em outros runtimes (`RUBYOPT`, `NODE_OPTIONS`, etc.): sempre que um interpretador é iniciado por um wrapper privilegiado, procure por env vars que modifiquem **module loading** ou **startup behavior**.

Do ponto de vista de post-exploitation, lembre-se também de que environments herdados frequentemente contêm **credentials**, **proxy settings**, **service tokens** ou **cloud keys**. Confira [Linux Post Exploitation](linux-post-exploitation/README.md) para caça a `/proc/<PID>/environ` e `Environment=` do `systemd`.

### PS1

Altere a aparência do seu prompt.

[**This is an example**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../images/image (897).png>)

Regular user:

![](<../images/image (740).png>)

One, two and three backgrounded jobs:

![](<../images/image (145).png>)

One background job, one stopped and last command didn't finish correctly:

![](<../images/image (715).png>)

## References

- [GNU Bash Manual - Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)

{{#include ../banners/hacktricks-training.md}}
