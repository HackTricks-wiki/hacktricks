# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces são o recurso do kernel que faz um container parecer "sua própria máquina" mesmo sendo na verdade apenas uma árvore de processos do host. Eles não criam um novo kernel e não virtualizam tudo, mas permitem que o kernel apresente visões diferentes de recursos selecionados para grupos distintos de processos. Esse é o núcleo da ilusão do container: a carga de trabalho vê um sistema de arquivos, tabela de processos, pilha de rede, hostname, recursos IPC e um modelo de identidade de usuário/grupo que aparentam ser locais, mesmo que o sistema subjacente seja compartilhado.

É por isso que namespaces são o primeiro conceito que a maioria das pessoas encontra ao aprender como containers funcionam. Ao mesmo tempo, são um dos conceitos mais comumente mal compreendidos porque os leitores frequentemente assumem que "tem namespaces" significa "está isolado com segurança". Na realidade, um namespace isola apenas a classe específica de recursos para a qual foi projetado. Um processo pode ter um PID namespace privado e ainda ser perigoso porque possui um bind mount do host gravável. Pode ter um network namespace privado e ainda ser perigoso porque retém `CAP_SYS_ADMIN` e roda sem seccomp. Namespaces são fundamentais, mas são apenas uma camada na fronteira final.

## Namespace Types

Containers Linux comumente dependem de vários tipos de namespace ao mesmo tempo. O **mount namespace** dá ao processo uma tabela de mount separada e, portanto, uma visão controlada do sistema de arquivos. O **PID namespace** altera a visibilidade e a numeração dos processos para que a carga de trabalho veja sua própria árvore de processos. O **network namespace** isola interfaces, rotas, sockets e o estado do firewall. O **IPC namespace** isola SysV IPC e filas de mensagens POSIX. O **UTS namespace** isola o hostname e o nome de domínio NIS. O **user namespace** remapeia IDs de usuário e grupo de modo que root dentro do container não signifique necessariamente root no host. O **cgroup namespace** virtualiza a hierarquia de cgroups visível, e o **time namespace** virtualiza relógios selecionados em kernels mais recentes.

Cada um desses namespaces resolve um problema diferente. É por isso que a análise prática de segurança de containers frequentemente se resume a verificar **quais namespaces estão isolados** e **quais foram deliberadamente compartilhados com o host**.

## Host Namespace Sharing

Muitos breakouts de container não começam com uma vulnerabilidade do kernel. Começam com um operador enfraquecendo deliberadamente o modelo de isolamento. Os exemplos `--pid=host`, `--network=host`, e `--userns=host` são **flags de CLI no estilo Docker/Podman** usadas aqui como exemplos concretos de compartilhamento de namespace com o host. Outros runtimes expressam a mesma ideia de forma diferente. No Kubernetes os equivalentes geralmente aparecem como configurações do Pod tais como `hostPID: true`, `hostNetwork: true`, ou `hostIPC: true`. Em stacks de runtime de nível mais baixo, como containerd ou CRI-O, o mesmo comportamento costuma ser alcançado através da configuração OCI do runtime gerada, em vez de por uma flag exposta ao usuário com o mesmo nome. Em todos esses casos, o resultado é similar: a carga de trabalho deixa de receber a visão padrão de namespace isolado.

É por isso que revisões de namespace nunca devem parar em "o processo está em algum namespace". A pergunta importante é se o namespace é privado ao container, compartilhado com containers irmãos, ou conectado diretamente ao host. No Kubernetes a mesma ideia aparece com flags tais como `hostPID`, `hostNetwork` e `hostIPC`. Os nomes mudam entre plataformas, mas o padrão de risco é o mesmo: um namespace do host compartilhado torna os privilégios remanescentes do container e o estado do host alcançável muito mais relevantes.

## Inspection

A visão geral mais simples é:
```bash
ls -l /proc/self/ns
```
Cada entrada é um link simbólico com um identificador semelhante a inode. Se dois processos apontarem para o mesmo identificador de namespace, eles estão no mesmo namespace desse tipo. Isso torna `/proc` um local muito útil para comparar o processo atual com outros processos interessantes na máquina.

Esses comandos rápidos costumam ser suficientes para começar:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
A partir daí, o próximo passo é comparar o processo do container com processos do host ou processos vizinhos e determinar se um namespace é realmente privado ou não.

### Enumerando instâncias de namespace a partir do host

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
Se quiser encontrar quais processos pertencem a um identificador de namespace específico, troque `readlink` por `ls -l` e use grep para procurar o número do namespace alvo:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Esses comandos são úteis porque permitem determinar se um host está executando um workload isolado, vários workloads isolados, ou uma mistura de instâncias de namespace compartilhadas e privadas.

### Entrando em um namespace de destino

Quando o chamador tem privilégios suficientes, `nsenter` é a maneira padrão de entrar no namespace de outro processo:
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
O objetivo de listar essas formas juntas não é que toda avaliação precise de todas elas, mas sim que namespace-specific post-exploitation frequentemente se torna muito mais fácil quando o operador conhece a sintaxe exata de entrada em vez de lembrar apenas a forma all-namespaces.

## Páginas

As páginas seguintes explicam cada namespace com mais detalhes:

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

Ao lê-las, tenha em mente duas ideias. Primeiro, cada namespace isola apenas um tipo de visão. Segundo, um namespace privado é útil somente se o restante do modelo de privilégio ainda tornar esse isolamento significativo.

## Padrões de runtime

| Runtime / platform | Default namespace posture | Common manual weakening |
| --- | --- | --- |
| Docker Engine | Novos namespaces mount, PID, network, IPC e UTS por padrão; user namespaces estão disponíveis mas não habilitados por padrão em setups rootful padrão | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | Novos namespaces por padrão; rootless Podman usa automaticamente um user namespace; os padrões do cgroup namespace dependem da versão do cgroup | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Por padrão, os Pods **não** compartilham host PID, network ou IPC; a rede do Pod é privada ao Pod, não a cada container individual; user namespaces são opt-in via `spec.hostUsers: false` em clusters suportados | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omission of user-namespace opt-in, privileged workload settings |
| containerd / CRI-O under Kubernetes | Normalmente seguem os padrões dos Pods do Kubernetes | mesmo que a linha do Kubernetes; especificações CRI/OCI diretas também podem solicitar junções em namespaces do host |

A regra principal de portabilidade é simples: o **conceito** de compartilhamento de namespace do host é comum entre runtimes, mas a **sintaxe** é específica de cada runtime.
{{#include ../../../../../banners/hacktricks-training.md}}
