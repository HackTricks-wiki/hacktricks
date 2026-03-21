# Espaços de nomes

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces são o recurso do kernel que faz um container parecer "sua própria máquina" mesmo que, na verdade, seja apenas uma árvore de processos do host. Eles não criam um novo kernel e não virtualizam tudo, mas permitem que o kernel apresente visões diferentes de recursos selecionados para diferentes grupos de processos. Essa é a essência da ilusão do container: a carga de trabalho vê um filesystem, tabela de processos, network stack, hostname, recursos de IPC e um modelo de identidade user/group que parecem locais, apesar de o sistema subjacente ser compartilhado.

Por isso namespaces são o primeiro conceito que a maioria das pessoas encontra ao aprender como containers funcionam. Ao mesmo tempo, são um dos conceitos mais comumente mal compreendidos porque leitores frequentemente assumem que "tem namespaces" significa "está isolado com segurança". Na realidade, um namespace isola apenas a classe específica de recursos para a qual foi projetado. Um processo pode ter um PID namespace privado e ainda ser perigoso porque possui um bind mount do host gravável. Pode ter um network namespace privado e ainda ser perigoso porque mantém `CAP_SYS_ADMIN` e é executado sem seccomp. Namespaces são fundamentais, mas são apenas uma camada na fronteira final.

## Tipos de Namespace

Containers Linux comumente dependem de vários tipos de namespace ao mesmo tempo. O **mount namespace** dá ao processo uma tabela de mounts separada e, portanto, uma visão controlada do filesystem. O **PID namespace** altera a visibilidade e a numeração dos processos para que a carga de trabalho veja sua própria árvore de processos. O **network namespace** isola interfaces, rotas, sockets e estado de firewall. O **IPC namespace** isola SysV IPC e filas de mensagens POSIX. O **UTS namespace** isola hostname e NIS domain name. O **user namespace** remapeia user e group IDs de modo que root dentro do container não signifique necessariamente root no host. O **cgroup namespace** virtualiza a hierarquia de cgroup visível, e o **time namespace** virtualiza clocks selecionados em kernels mais novos.

Cada um desses namespaces resolve um problema diferente. Por isso a análise prática de segurança de containers muitas vezes se resume a checar **quais namespaces estão isolados** e **quais foram deliberadamente compartilhados com o host**.

## Compartilhamento de Namespace com o Host

Muitas escaladas de container não começam com uma vulnerabilidade do kernel. Começam com um operador enfraquecendo deliberadamente o modelo de isolamento. Os exemplos `--pid=host`, `--network=host`, e `--userns=host` são **flags de CLI no estilo Docker/Podman** usadas aqui como exemplos concretos de compartilhamento de namespace com o host. Outros runtimes expressam a mesma ideia de forma diferente. No Kubernetes os equivalentes normalmente aparecem como configurações do Pod tais como `hostPID: true`, `hostNetwork: true`, ou `hostIPC: true`. Em stacks de runtime de nível mais baixo como containerd ou CRI-O, o mesmo comportamento frequentemente é alcançado através da configuração OCI gerada em vez de uma flag voltada ao usuário com o mesmo nome. Em todos esses casos, o resultado é similar: a carga de trabalho deixa de receber a visão de namespace isolada por padrão.

Por isso revisões de namespaces nunca deveriam parar em "o processo está em algum namespace". A pergunta importante é se o namespace é privado para o container, compartilhado com containers irmãos, ou unido diretamente ao host. No Kubernetes a mesma ideia aparece com flags tais como `hostPID`, `hostNetwork`, e `hostIPC`. Os nomes mudam entre plataformas, mas o padrão de risco é o mesmo: um namespace compartilhado com o host faz com que os privilégios remanescentes do container e o estado do host alcançável tornem-se muito mais significativos.

## Inspeção

A visão geral mais simples é:
```bash
ls -l /proc/self/ns
```
Cada entrada é um link simbólico com um identificador semelhante a um inode. Se dois processos apontam para o mesmo identificador de namespace, eles estão no mesmo namespace desse tipo. Isso torna `/proc` um local muito útil para comparar o processo atual com outros processos interessantes na máquina.

Estes comandos rápidos geralmente são suficientes para começar:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
A partir daí, o próximo passo é comparar o processo do container com processos do host ou processos vizinhos e determinar se um namespace é realmente privado ou não.

### Enumerando instâncias de namespace a partir do host

Quando você já tem acesso ao host e quer entender quantas instâncias de namespace distintas de um determinado tipo existem, `/proc` fornece um inventário rápido:
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
Se você quer encontrar quais processos pertencem a um identificador de namespace específico, troque `readlink` por `ls -l` e faça `grep` pelo número do namespace alvo:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Esses comandos são úteis porque permitem responder se um host está executando uma única workload isolada, muitas workloads isoladas ou uma mistura de instâncias de namespace compartilhadas e privadas.

### Entrando em um Target Namespace

Quando o processo chamador tem privilégios suficientes, `nsenter` é a forma padrão de entrar no namespace de outro processo:
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
O objetivo de listar essas formas juntas não é que toda avaliação precise de todas elas, mas que namespace-specific post-exploitation frequentemente se torna muito mais fácil uma vez que o operador conhece a sintaxe exata de entrada ao invés de lembrar apenas a forma all-namespaces.

## Pages

The following pages explain each namespace in more detail:

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

Ao lê-las, mantenha duas ideias em mente. Primeiro, cada namespace isola apenas um tipo de visão. Segundo, um namespace privado é útil somente se o restante do modelo de privilégios ainda tornar esse isolamento significativo.

## Runtime Defaults

| Runtime / plataforma | Postura padrão de namespace | Enfraquecimentos manuais comuns |
| --- | --- | --- |
| Docker Engine | Novos mount, PID, network, IPC e UTS namespaces por padrão; user namespaces estão disponíveis mas não habilitados por padrão em setups rootful padrão | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | Novos namespaces por padrão; rootless Podman automaticamente usa um user namespace; defaults do cgroup namespace dependem da versão do cgroup | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods do **not** share host PID, network, or IPC por padrão; a rede do Pod é privada para o Pod, não para cada container individual; user namespaces são opt-in via `spec.hostUsers: false` em clusters suportados | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omitting user-namespace opt-in, privileged workload settings |
| containerd / CRI-O under Kubernetes | Normalmente seguem os defaults do Pod do Kubernetes | same as Kubernetes row; direct CRI/OCI specs can also request host namespace joins |

A regra principal de portabilidade é simples: o conceito de compartilhamento de host namespaces é comum entre runtimes, mas a sintaxe é específica de cada runtime.
