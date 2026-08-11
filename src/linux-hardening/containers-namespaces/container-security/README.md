# Segurança de Containers

{{#include ../../../banners/hacktricks-training.md}}

## O Que Um Container Realmente É

Uma forma prática de definir um container é a seguinte: um container é uma **árvore regular de processos Linux** iniciada sob uma configuração específica no estilo OCI, para que veja um sistema de arquivos controlado, um conjunto controlado de recursos do kernel e um modelo de privilégios restrito. O processo pode acreditar que é o PID 1, pode acreditar que possui sua própria pilha de rede, pode acreditar que controla seu próprio hostname e seus próprios recursos de IPC, e pode até mesmo ser executado como root dentro do próprio user namespace. Porém, nos bastidores, ele ainda é um processo do host que o kernel agenda como qualquer outro.

É por isso que a segurança de containers é, na prática, o estudo de como essa ilusão é construída e de como ela falha. Se o mount namespace for fraco, o processo poderá ver o sistema de arquivos do host. Se o user namespace estiver ausente ou desabilitado, o root dentro do container poderá ser mapeado de forma muito próxima ao root no host. Se o seccomp estiver unconfined e o conjunto de capabilities for amplo demais, o processo poderá acessar syscalls e recursos privilegiados do kernel que deveriam permanecer inacessíveis. Se o runtime socket estiver montado dentro do container, o container talvez nem precise de um kernel breakout, pois poderá simplesmente solicitar ao runtime que inicie outro container sibling mais poderoso ou monte diretamente o sistema de arquivos raiz do host.

## Como Containers Diferem de Máquinas Virtuais

Uma VM normalmente possui seu próprio kernel e uma camada de abstração de hardware. Isso significa que o kernel guest pode travar, entrar em panic ou ser explorado sem implicar automaticamente controle direto sobre o kernel do host. Em containers, o workload não recebe um kernel separado. Em vez disso, recebe uma visão cuidadosamente filtrada e organizada em namespaces do mesmo kernel usado pelo host. Como resultado, containers normalmente são mais leves, iniciam mais rapidamente, permitem maior densidade de workloads em uma máquina e são mais adequados à implantação de aplicações de curta duração. O preço é que o limite de isolamento depende muito mais diretamente da configuração correta do host e do runtime.

Isso não significa que containers sejam "inseguros" e VMs sejam "seguras". Significa que o modelo de segurança é diferente. Uma stack de containers bem configurada, com execução rootless, user namespaces, seccomp padrão, um conjunto restrito de capabilities, nenhum compartilhamento de host namespaces e uma aplicação rigorosa de SELinux ou AppArmor, pode ser bastante robusta. Por outro lado, um container iniciado com `--privileged`, compartilhamento do host PID/network, o Docker socket montado dentro dele e um bind mount gravável de `/` fica funcionalmente muito mais próximo do acesso root ao host do que de um application sandbox isolado com segurança. A diferença vem das camadas que foram habilitadas ou desabilitadas.

Também existe um meio-termo que os leitores devem compreender, pois ele aparece cada vez mais em ambientes reais. **Sandboxed container runtimes**, como **gVisor** e **Kata Containers**, reforçam intencionalmente o limite de segurança além de um container `runc` clássico. O gVisor coloca uma camada de kernel em userspace entre o workload e muitas interfaces do kernel do host, enquanto o Kata inicia o workload dentro de uma máquina virtual leve. Eles ainda são usados por meio de ecossistemas de containers e workflows de orquestração, mas suas propriedades de segurança diferem das dos runtimes OCI simples e eles não devem ser mentalmente agrupados com "containers Docker normais", como se tudo se comportasse da mesma forma.

## A Stack de Containers: Várias Camadas, Não Uma Só

Quando alguém diz "este container é inseguro", a pergunta de acompanhamento útil é: **qual camada o tornou inseguro?** Um workload containerizado normalmente é resultado do trabalho conjunto de vários componentes.

No nível superior, geralmente existe uma **camada de image build**, como BuildKit, Buildah ou Kaniko, que cria a image OCI e seus metadados. Acima do runtime de baixo nível, pode haver um **engine ou manager**, como Docker Engine, Podman, containerd, CRI-O, Incus ou systemd-nspawn. Em ambientes de cluster, também pode haver um **orchestrator**, como Kubernetes, decidindo a postura de segurança solicitada por meio da configuração do workload. Por fim, o **kernel** é o componente que realmente aplica namespaces, cgroups, seccomp e a política MAC.

Esse modelo em camadas é importante para compreender os defaults. Uma restrição pode ser solicitada pelo Kubernetes, traduzida por meio do CRI pelo containerd ou CRI-O, convertida em uma OCI spec pelo runtime wrapper e somente então aplicada pelo `runc`, `crun`, `runsc` ou outro runtime contra o kernel. Quando os defaults diferem entre ambientes, geralmente é porque uma dessas camadas alterou a configuração final. O mesmo mecanismo pode, portanto, aparecer no Docker ou Podman como uma CLI flag, no Kubernetes como um campo de Pod ou `securityContext`, e em stacks de runtime de nível inferior como uma configuração OCI gerada para o workload. Por esse motivo, os exemplos de CLI nesta seção devem ser lidos como **sintaxe específica de runtime para um conceito geral de container**, e não como flags universais suportadas por todas as ferramentas.

## O Verdadeiro Limite de Segurança do Container

Na prática, a segurança de containers vem de **controles sobrepostos**, não de um único controle perfeito. Namespaces isolam a visibilidade. cgroups controlam e limitam o uso de recursos. Capabilities reduzem o que um processo aparentemente privilegiado pode realmente fazer. seccomp bloqueia syscalls perigosas antes que cheguem ao kernel. AppArmor e SELinux adicionam Mandatory Access Control sobre as verificações DAC normais. `no_new_privs`, caminhos mascarados do procfs e caminhos de sistema somente leitura tornam mais difíceis as cadeias comuns de abuso de privilégios e de proc/sys. O próprio runtime também importa, pois decide como mounts, sockets, labels e joins de namespaces são criados.

É por isso que grande parte da documentação de segurança de containers parece repetitiva. A mesma cadeia de escape geralmente depende de vários mecanismos ao mesmo tempo. Por exemplo, um host bind mount gravável é problemático, mas se torna muito pior se o container também for executado como root real no host, tiver `CAP_SYS_ADMIN`, estiver unconfined pelo seccomp e não for restringido pelo SELinux ou AppArmor. Da mesma forma, o compartilhamento do host PID é uma exposição séria, mas torna-se significativamente mais útil para um atacante quando combinado com `CAP_SYS_PTRACE`, proteções fracas do procfs ou ferramentas de entrada em namespaces, como `nsenter`. Portanto, a forma correta de documentar o tema não é repetir o mesmo ataque em todas as páginas, mas explicar o que cada camada contribui para o limite final.

## Como Ler Esta Seção

A seção está organizada dos conceitos mais gerais aos mais específicos.

Comece pela visão geral do runtime e do ecossistema:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Em seguida, revise os control planes e as superfícies da supply chain que frequentemente determinam se um atacante sequer precisa de um kernel escape:

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

As páginas sobre cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, caminhos mascarados e caminhos de sistema somente leitura explicam os mecanismos normalmente sobrepostos aos namespaces:

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

## Uma Boa Mentalidade para a Primeira Enumeração

Ao avaliar um target containerizado, é muito mais útil fazer um pequeno conjunto de perguntas técnicas precisas do que pular imediatamente para PoCs famosas de escape. Primeiro, identifique a **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer ou algo mais especializado. Depois, identifique o **runtime**: `runc`, `crun`, `runsc`, `kata-runtime` ou outra implementação compatível com OCI. Em seguida, verifique se o ambiente é **rootful ou rootless**, se **user namespaces** estão ativos, se algum **host namespace** é compartilhado, quais **capabilities** permanecem, se o **seccomp** está habilitado, se uma **política MAC** está realmente sendo aplicada, se existem **mounts ou sockets perigosos** e se o processo pode interagir com a API do container runtime.

Essas respostas informam muito mais sobre a postura de segurança real do que o nome da base image. Em muitas avaliações, é possível prever a provável família de breakout antes mesmo de ler um único arquivo da aplicação, apenas compreendendo a configuração final do container.

## Cobertura

Esta seção abrange o conteúdo antigo focado no Docker, reorganizado em torno de containers: exposição do runtime e do daemon, authorization plugins, confiança em images e build secrets, sensitive host mounts, workloads distroless, containers privilegiados e as proteções do kernel normalmente sobrepostas à execução de containers.

{{#include ../../../banners/hacktricks-training.md}}
