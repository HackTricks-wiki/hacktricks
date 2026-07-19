# Segurança de Containers

{{#include ../../../banners/hacktricks-training.md}}

## O Que Um Container Realmente É

Uma forma prática de definir um container é esta: um container é uma **árvore de processos Linux regular** iniciada sob uma configuração específica no estilo OCI, para que ela veja um filesystem controlado, um conjunto controlado de recursos do kernel e um modelo de privilégios restrito. O processo pode acreditar que é o PID 1, pode acreditar que possui sua própria network stack, pode acreditar que é proprietário do próprio hostname e dos próprios recursos de IPC, e pode até ser executado como root dentro do próprio user namespace. Porém, nos bastidores, ele ainda é um processo do host que o kernel agenda como qualquer outro.

É por isso que a segurança de containers é, na prática, o estudo de como essa ilusão é construída e como ela falha. Se o mount namespace for fraco, o processo poderá ver o filesystem do host. Se o user namespace estiver ausente ou desabilitado, o root dentro do container poderá mapear-se de forma muito próxima ao root no host. Se o seccomp estiver unconfined e o conjunto de capabilities for amplo demais, o processo poderá acessar syscalls e recursos privilegiados do kernel que deveriam permanecer inacessíveis. Se o runtime socket estiver montado dentro do container, o container talvez nem precise de um kernel breakout, pois poderá simplesmente solicitar ao runtime que inicie um container sibling mais poderoso ou monte diretamente o filesystem root do host.

## Como Containers Diferem de Virtual Machines

Uma VM normalmente possui seu próprio kernel e uma camada de abstração de hardware. Isso significa que o kernel guest pode falhar, entrar em panic ou ser explorado sem necessariamente implicar controle direto do kernel host. Em containers, o workload não recebe um kernel separado. Em vez disso, recebe uma visão cuidadosamente filtrada e organizada em namespaces do mesmo kernel usado pelo host. Como resultado, containers normalmente são mais leves, iniciam mais rápido, são mais fáceis de empacotar densamente em uma máquina e são mais adequados para deployment de aplicações de curta duração. O preço é que a boundary de isolamento depende muito mais diretamente da configuração correta do host e do runtime.

Isso não significa que containers sejam "insecure" e VMs sejam "secure". Significa que o modelo de segurança é diferente. Uma stack de containers bem configurada, com execução rootless, user namespaces, seccomp padrão, um conjunto rigoroso de capabilities, sem compartilhamento de host namespaces e com aplicação forte de SELinux ou AppArmor, pode ser muito robusta. Por outro lado, um container iniciado com `--privileged`, compartilhamento do host PID/network, Docker socket montado dentro dele e um bind mount gravável de `/` fica funcionalmente muito mais próximo de um acesso root ao host do que de um application sandbox isolado com segurança. A diferença vem das camadas que foram habilitadas ou desabilitadas.

Também existe um meio-termo que os leitores devem compreender, pois ele aparece cada vez mais em ambientes reais. **Sandboxed container runtimes**, como **gVisor** e **Kata Containers**, reforçam intencionalmente a boundary além de um container `runc` clássico. O gVisor coloca uma camada de kernel em userspace entre o workload e muitas interfaces do kernel host, enquanto o Kata executa o workload dentro de uma lightweight virtual machine. Eles ainda são usados por meio de ecossistemas de containers e workflows de orchestration, mas suas propriedades de segurança diferem das de runtimes OCI simples e não devem ser mentalmente agrupados com "normal Docker containers", como se tudo se comportasse da mesma forma.

## A Stack de Containers: Várias Camadas, Não Uma Só

Quando alguém diz "este container é insecure", a pergunta útil seguinte é: **qual camada o tornou insecure?** Um workload containerizado normalmente é resultado do trabalho conjunto de vários componentes.

No topo, geralmente existe uma **camada de build da image**, como BuildKit, Buildah ou Kaniko, que cria a OCI image e os metadados. Acima do runtime de baixo nível, pode haver um **engine ou manager**, como Docker Engine, Podman, containerd, CRI-O, Incus ou systemd-nspawn. Em ambientes de cluster, também pode haver um **orchestrator**, como Kubernetes, decidindo a postura de segurança solicitada por meio da configuração do workload. Finalmente, o **kernel** é o componente que realmente aplica namespaces, cgroups, seccomp e a MAC policy.

Esse modelo em camadas é importante para entender os defaults. Uma restrição pode ser solicitada pelo Kubernetes, traduzida por meio do CRI pelo containerd ou CRI-O, convertida em uma OCI spec pelo runtime wrapper e somente então aplicada pelo `runc`, `crun`, `runsc` ou outro runtime contra o kernel. Quando os defaults diferem entre ambientes, geralmente é porque uma dessas camadas alterou a configuração final. O mesmo mecanismo pode, portanto, aparecer no Docker ou Podman como uma CLI flag, no Kubernetes como um campo de Pod ou `securityContext`, e em stacks de runtime de baixo nível como uma configuração OCI gerada para o workload. Por esse motivo, os exemplos de CLI nesta seção devem ser lidos como **sintaxe específica do runtime para um conceito geral de containers**, e não como flags universais suportadas por todas as ferramentas.

## A Verdadeira Boundary de Segurança do Container

Na prática, a segurança de containers vem de **controles sobrepostos**, não de um único controle perfeito. Namespaces isolam a visibilidade. cgroups controlam e limitam o uso de recursos. Capabilities reduzem o que um processo aparentemente privilegiado pode realmente fazer. seccomp bloqueia syscalls perigosas antes que elas cheguem ao kernel. AppArmor e SELinux adicionam Mandatory Access Control sobre as verificações DAC normais. `no_new_privs`, caminhos masked do procfs e system paths read-only tornam mais difíceis as cadeias comuns de privilege abuse e abuso de proc/sys. O próprio runtime também importa, pois decide como mounts, sockets, labels e namespace joins são criados.

É por isso que grande parte da documentação de segurança de containers parece repetitiva. A mesma cadeia de escape frequentemente depende de vários mecanismos ao mesmo tempo. Por exemplo, um host bind mount gravável é problemático, mas torna-se muito pior se o container também for executado como root real no host, tiver `CAP_SYS_ADMIN`, estiver unconfined pelo seccomp e não for restringido pelo SELinux ou AppArmor. Da mesma forma, o compartilhamento do host PID é uma exposição séria, mas torna-se muito mais útil para um atacante quando combinado com `CAP_SYS_PTRACE`, proteções fracas do procfs ou ferramentas de namespace-entry, como `nsenter`. Portanto, a forma correta de documentar o tema não é repetir o mesmo ataque em todas as páginas, mas explicar o que cada camada acrescenta à boundary final.

## Como Ler Esta Seção

A seção está organizada dos conceitos mais gerais aos mais específicos.

Comece pela visão geral do runtime e do ecossistema:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Depois, revise os control planes e as superfícies da supply chain que frequentemente determinam se um atacante sequer precisa de um kernel escape:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
authorization-plugins.md
{{#endref}}

{{#ref}}
image-security-and-secrets.md
{{#endref}}

{{#ref}}
assessment-and-hardening.md
{{#endref}}

Depois, avance para o modelo de proteção:

{{#ref}}
protections/
{{#endref}}

As páginas sobre namespaces explicam individualmente as primitivas de isolamento do kernel:

{{#ref}}
protections/namespaces/
{{#endref}}

As páginas sobre cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths e read-only system paths explicam os mecanismos normalmente colocados em camadas sobre os namespaces:

{{#ref}}
protections/cgroups.md
{{#endref}}

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/seccomp.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

{{#ref}}
protections/no-new-privileges.md
{{#endref}}

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

{{#ref}}
distroless.md
{{#endref}}

{{#ref}}
privileged-containers.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Uma Boa Mentalidade Inicial de Enumeration

Ao avaliar um target containerizado, é muito mais útil fazer um pequeno conjunto de perguntas técnicas precisas do que pular imediatamente para PoCs famosas de escape. Primeiro, identifique a **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer ou algo mais especializado. Depois, identifique o **runtime**: `runc`, `crun`, `runsc`, `kata-runtime` ou outra implementação compatível com OCI. Em seguida, verifique se o ambiente é **rootful ou rootless**, se **user namespaces** estão ativos, se algum **host namespace** é compartilhado, quais **capabilities** permanecem, se o **seccomp** está habilitado, se uma **MAC policy** está realmente sendo aplicada, se existem **mounts ou sockets perigosos** e se o processo pode interagir com a API do container runtime.

Essas respostas revelam muito mais sobre a postura de segurança real do que o nome da base image. Em muitas avaliações, é possível prever a provável família de breakout antes de ler um único arquivo da aplicação, simplesmente entendendo a configuração final do container.

## Cobertura

Esta seção cobre o material antigo focado em Docker, agora organizado em torno de containers: exposição do runtime e do daemon, authorization plugins, confiança em images e build secrets, sensitive host mounts, workloads distroless, privileged containers e as proteções do kernel normalmente aplicadas em camadas ao redor da execução de containers.
{{#include ../../../banners/hacktricks-training.md}}
