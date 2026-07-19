# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces são um recurso do kernel que faz um container parecer "sua própria máquina", embora ele seja, na realidade, apenas uma árvore de processos do host. Eles não criam um novo kernel nem virtualizam tudo, mas permitem que o kernel apresente diferentes visões de recursos selecionados a diferentes grupos de processos. Esse é o núcleo da ilusão de container: o workload vê um filesystem, uma tabela de processos, uma network stack, um hostname, recursos de IPC e um modelo de identidade de usuários/grupos que parecem locais, embora o sistema subjacente seja compartilhado.

É por isso que namespaces são o primeiro conceito que a maioria das pessoas encontra ao aprender como containers funcionam. Ao mesmo tempo, eles são um dos conceitos mais mal compreendidos, porque os leitores frequentemente presumem que "possui namespaces" significa "está isolado com segurança". Na realidade, um namespace isola apenas a classe específica de recursos para a qual foi projetado. Um processo pode ter um private PID namespace e ainda ser perigoso porque possui um writable host bind mount. Ele pode ter um private network namespace e ainda ser perigoso porque mantém `CAP_SYS_ADMIN` e executa sem seccomp. Namespaces são fundamentais, mas são apenas uma camada do boundary final.

## Tipos de namespaces

Linux containers geralmente dependem de vários tipos de namespaces ao mesmo tempo. O **mount namespace** fornece ao processo uma tabela de mounts separada e, portanto, uma visão controlada do filesystem. O **PID namespace** altera a visibilidade e a numeração dos processos, fazendo com que o workload veja sua própria árvore de processos. O **network namespace** isola interfaces, rotas, sockets e o estado do firewall. O **IPC namespace** isola SysV IPC e filas de mensagens POSIX. O **UTS namespace** isola o hostname e o nome de domínio NIS. O **user namespace** remapeia IDs de usuários e grupos, de modo que root dentro do container não signifique necessariamente root no host. O **cgroup namespace** virtualiza a hierarquia de cgroups visível, e o **time namespace** virtualiza clocks selecionados em kernels mais recentes.

Cada um desses namespaces resolve um problema diferente. É por isso que a análise prática de container security frequentemente se resume a verificar **quais namespaces estão isolados** e **quais foram deliberadamente compartilhados com o host**.

## Compartilhamento de namespaces do host

Muitos container breakouts não começam com uma vulnerabilidade do kernel. Eles começam com um operador enfraquecendo deliberadamente o modelo de isolamento. Os exemplos `--pid=host`, `--network=host` e `--userns=host` são **Docker/Podman-style CLI flags** usados aqui como exemplos concretos de compartilhamento de namespaces do host. Outros runtimes expressam a mesma ideia de forma diferente. No Kubernetes, os equivalentes geralmente aparecem como configurações de Pod, como `hostPID: true`, `hostNetwork: true` ou `hostIPC: true`. Em runtime stacks de nível mais baixo, como containerd ou CRI-O, o mesmo comportamento geralmente é obtido por meio da configuração de runtime OCI gerada, em vez de uma flag voltada ao usuário com o mesmo nome. Em todos esses casos, o resultado é semelhante: o workload não recebe mais a visão padrão de namespace isolada.

É por isso que as revisões de namespaces nunca devem parar em "o processo está em algum namespace". A questão importante é saber se o namespace é privado para o container, compartilhado com containers irmãos ou ingressado diretamente no host. No Kubernetes, a mesma ideia aparece com flags como `hostPID`, `hostNetwork` e `hostIPC`. Os nomes mudam entre as plataformas, mas o padrão de risco é o mesmo: um namespace compartilhado com o host torna os privilégios restantes do container e o estado do host que pode ser alcançado muito mais relevantes.

## Inspeção

A visão geral mais simples é:
```bash
ls -l /proc/self/ns
```
Cada entrada é um link simbólico com um identificador semelhante a um inode. Se dois processos apontarem para o mesmo identificador de namespace, eles estarão no mesmo namespace desse tipo. Isso torna `/proc` um local muito útil para comparar o processo atual com outros processos interessantes na máquina.

Estes comandos rápidos geralmente são suficientes para começar:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
A partir daí, o próximo passo é comparar o processo do container com os processos do host ou de containers vizinhos e determinar se um namespace é realmente privado ou não.

### Enumerando Instâncias de Namespace a Partir do Host

Quando você já tem acesso ao host e quer entender quantos namespaces distintos de um determinado tipo existem, `/proc` fornece um inventário rápido:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name pid    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name net    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name ipc    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name uts    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name user   -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name time   -exec readlink {} \; 2>/dev/null | sort -u
```
Se quiser descobrir quais processos pertencem a um identificador de namespace específico, troque `readlink` por `ls -l` e use grep para procurar o número do namespace de destino:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Esses comandos são úteis porque permitem determinar se um host está executando uma única carga de trabalho isolada, várias cargas de trabalho isoladas ou uma combinação de instâncias de namespace compartilhadas e privadas.

### Entrando em um Namespace de Destino

Quando o chamador tem privilégios suficientes, `nsenter` é a forma padrão de ingressar no namespace de outro processo:
```bash
nsenter -m TARGET_PID --pid /bin/bash   # mount
nsenter -t TARGET_PID --pid /bin/bash   # pid
nsenter -n TARGET_PID --pid /bin/bash   # network
nsenter -i TARGET_PID --pid /bin/bash   # ipc
nsenter -u TARGET_PID --pid /bin/bash   # uts
nsenter -U TARGET_PID --pid /bin/bash   # user
nsenter -C TARGET_PID --pid /bin/bash   # cgroup
nsenter -T TARGET_PID --pid /bin/bash   # time
```
O objetivo de listar essas formas juntas não é dizer que toda avaliação precisa de todas elas, mas que o post-exploitation específico de namespaces geralmente se torna muito mais fácil quando o operador conhece a sintaxe exata de entrada, em vez de lembrar apenas a forma para todos os namespaces.

## Páginas

As páginas a seguir explicam cada namespace em mais detalhes:

{{#ref}}
mount-namespace.md
{{#endref}}

{{#ref}}
pid-namespace.md
{{#endref}}

{{#ref}}
network-namespace.md
{{#endref}}

{{#ref}}
ipc-namespace.md
{{#endref}}

{{#ref}}
uts-namespace.md
{{#endref}}

{{#ref}}
user-namespace.md
{{#endref}}

{{#ref}}
cgroup-namespace.md
{{#endref}}

{{#ref}}
time-namespace.md
{{#endref}}

Ao lê-las, mantenha duas ideias em mente. Primeiro, cada namespace isola apenas um tipo de visão. Segundo, um namespace privado só é útil se o restante do modelo de privilégios ainda fizer com que esse isolamento seja significativo.

## Padrões de Runtime

| Runtime / plataforma | Configuração padrão de namespaces | Enfraquecimento manual comum |
| --- | --- | --- |
| Docker Engine | Novos namespaces de mount, PID, network, IPC e UTS por padrão; user namespaces estão disponíveis, mas não são habilitados por padrão em configurações rootful padrão | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | Novos namespaces por padrão; o Podman rootless usa automaticamente um user namespace; os padrões do cgroup namespace dependem da versão do cgroup | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods **não** compartilham o PID, network ou IPC do host por padrão; a rede do Pod é privada para o Pod, não para cada container individual; user namespaces são opt-in via `spec.hostUsers: false` em clusters compatíveis | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omissão do opt-in de user namespace, configurações de workload privilegiado |
| containerd / CRI-O no Kubernetes | Geralmente seguem os padrões de Pod do Kubernetes | igual à linha do Kubernetes; especificações CRI/OCI diretas também podem solicitar joins a namespaces do host |

A principal regra de portabilidade é simples: o **conceito** de compartilhamento de namespaces do host é comum entre os runtimes, mas a **sintaxe** é específica de cada runtime.
{{#include ../../../../../banners/hacktricks-training.md}}
