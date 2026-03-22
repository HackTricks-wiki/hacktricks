# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces são a funcionalidade do kernel que faz um container parecer "sua própria máquina" mesmo que, na verdade, seja apenas uma árvore de processos do host. Eles não criam um kernel novo e não virtualizam tudo, mas permitem que o kernel apresente visões diferentes de recursos selecionados para diferentes grupos de processos. Esse é o cerne da ilusão do container: a carga de trabalho vê um sistema de arquivos, tabela de processos, pilha de rede, nome do host, recursos IPC e um modelo de identidade de usuário/grupo que aparentam ser locais, mesmo que o sistema subjacente seja compartilhado.

É por isso que namespaces são o primeiro conceito com que a maioria das pessoas se depara ao aprender como containers funcionam. Ao mesmo tempo, são um dos conceitos mais comumente mal compreendidos porque leitores frequentemente assumem que "tem namespaces" significa "está isolado com segurança". Na realidade, um namespace isola apenas a classe específica de recursos para a qual foi projetado. Um processo pode ter um PID namespace privado e ainda ser perigoso porque tem um bind mount do host gravável. Pode ter um network namespace privado e ainda ser perigoso porque mantém `CAP_SYS_ADMIN` e roda sem seccomp. Namespaces são fundamentais, mas são apenas uma camada na fronteira final.

## Tipos de Namespace

Linux containers comumente dependem de vários tipos de namespace ao mesmo tempo. A **mount namespace** dá ao processo uma tabela de mounts separada e, portanto, uma visão controlada do sistema de arquivos. A **PID namespace** altera a visibilidade e a numeração dos processos de modo que a carga de trabalho vê sua própria árvore de processos. A **network namespace** isola interfaces, rotas, sockets e o estado do firewall. A **IPC namespace** isola SysV IPC e filas de mensagens POSIX. A **UTS namespace** isola o nome do host e o NIS domain name. A **user namespace** remapeia user e group IDs de modo que root dentro do container não signifique necessariamente root no host. A **cgroup namespace** virtualiza a hierarquia de cgroups visível, e a **time namespace** virtualiza relógios selecionados em kernels mais novos.

Cada um desses namespaces resolve um problema diferente. Por isso a análise prática de segurança de containers frequentemente se resume a verificar **quais namespaces estão isolados** e **quais foram deliberadamente compartilhados com o host**.

## Compartilhamento de namespace com o host

Muitos escapes de container não começam com uma vulnerabilidade do kernel. Eles começam com um operador enfraquecendo deliberadamente o modelo de isolamento. Os exemplos `--pid=host`, `--network=host` e `--userns=host` são **Docker/Podman-style CLI flags** usados aqui como exemplos concretos de compartilhamento de namespace com o host. Outros runtimes expressam a mesma ideia de forma diferente. Em Kubernetes os equivalentes geralmente aparecem como configurações do Pod, tais como `hostPID: true`, `hostNetwork: true` ou `hostIPC: true`. Em stacks de runtime de nível mais baixo, como containerd ou CRI-O, o mesmo comportamento é frequentemente obtido através da configuração do OCI runtime gerada, em vez de por uma flag exposta ao usuário com o mesmo nome. Em todos esses casos, o resultado é similar: a carga de trabalho deixa de receber a visão padrão de namespace isolado.

É por isso que a revisão de namespaces nunca deve parar em "o processo está em algum namespace". A pergunta importante é se o namespace é privado ao container, compartilhado com containers irmãos ou conectado diretamente ao host. Em Kubernetes a mesma ideia aparece com flags como `hostPID`, `hostNetwork` e `hostIPC`. Os nomes mudam entre plataformas, mas o padrão de risco é o mesmo: um namespace compartilhado com o host torna os privilégios remanescentes do container e o estado do host alcançável muito mais significativos.

## Inspeção

A visão geral mais simples é:
```bash
ls -l /proc/self/ns
```
Cada entrada é um link simbólico com um identificador semelhante a um inode. Se dois processos apontam para o mesmo identificador de namespace, eles estão no mesmo namespace desse tipo. Isso torna `/proc` um local muito útil para comparar o processo atual com outros processos interessantes na máquina.

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
Para descobrir quais processos pertencem a um identificador de namespace específico, em vez de `readlink` use `ls -l` e `grep` pelo número do namespace alvo:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Estes comandos são úteis porque permitem responder se um host está executando uma única carga de trabalho isolada, várias cargas de trabalho isoladas, ou uma mistura de instâncias de namespace compartilhadas e privadas.

### Entrando em um namespace alvo

Quando o chamador tem privilégios suficientes, `nsenter` é a forma padrão de entrar no namespace de outro processo:
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
O objetivo de listar essas formas juntas não é que toda avaliação precise de todas elas, mas que post-exploitation específico de namespace frequentemente se torne muito mais fácil uma vez que o operador saiba a sintaxe exata de entrada em vez de lembrar apenas da forma all-namespaces.

## Páginas

As páginas a seguir explicam cada namespace com mais detalhe:

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

Ao lê-las, mantenha duas ideias em mente. Primeiro, cada namespace isola apenas um tipo de visão. Segundo, um namespace privado é útil somente se o resto do modelo de privilégios ainda tornar esse isolamento significativo.

## Padrões de tempo de execução

| Runtime / plataforma | Postura padrão de namespace | Enfraquecimento manual comum |
| --- | --- | --- |
| Docker Engine | Cria novos namespaces de mount, PID, network, IPC e UTS por padrão; user namespaces estão disponíveis mas não habilitados por padrão em configurações rootful padrão | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | Novos namespaces por padrão; rootless Podman usa automaticamente um user namespace; os defaults do cgroup namespace dependem da versão do cgroup | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods **não** compartilham PID, network ou IPC do host por padrão; o networking do Pod é privado ao Pod, não a cada container individual; user namespaces são opt-in via `spec.hostUsers: false` em clusters com suporte | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omissão do opt-in de user-namespace, configurações de workload privilegiado |
| containerd / CRI-O under Kubernetes | Geralmente seguem os defaults de Pod do Kubernetes | mesmo que a linha do Kubernetes; especificações diretas CRI/OCI também podem solicitar joins a namespaces do host |

A regra principal de portabilidade é simples: o **conceito** de compartilhamento de namespace do host é comum entre runtimes, mas a **sintaxe** é específica do runtime.
{{#include ../../../../../banners/hacktricks-training.md}}
