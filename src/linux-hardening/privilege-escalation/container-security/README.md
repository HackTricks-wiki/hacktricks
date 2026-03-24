# Segurança de Containers

{{#include ../../../banners/hacktricks-training.md}}

## O que um Container Realmente É

Uma forma prática de definir um container é esta: um container é uma **regular Linux process tree** que foi iniciada sob uma configuração específica no estilo OCI de modo que vê um filesystem controlado, um conjunto controlado de recursos do kernel e um modelo de privilégios restrito. O processo pode acreditar que é PID 1, pode acreditar que possui sua própria network stack, pode acreditar que é dono do seu próprio hostname e recursos de IPC, e pode até executar como root dentro do seu próprio user namespace. Mas por baixo do capô continua sendo um processo do host que o kernel agenda como qualquer outro.

É por isso que segurança de containers é realmente o estudo de como essa ilusão é construída e como ela falha. Se o mount namespace é fraco, o processo pode ver o filesystem do host. Se o user namespace está ausente ou desativado, root dentro do container pode mapear-se demasiadamente ao root do host. Se seccomp não está confinado e o conjunto de capabilities é muito amplo, o processo pode alcançar syscalls e funcionalidades privilegiadas do kernel que deveriam ficar fora de alcance. Se o runtime socket está montado dentro do container, o container pode nem precisar de um kernel breakout porque pode simplesmente pedir ao runtime para lançar um container irmão mais poderoso ou montar diretamente o filesystem raiz do host.

## Como Containers Diferem de Virtual Machines

Uma VM normalmente carrega seu próprio kernel e boundary de abstração de hardware. Isso significa que o guest kernel pode travar, panicar ou ser explorado sem implicar automaticamente controle direto do kernel do host. Em containers, a carga de trabalho não recebe um kernel separado. Em vez disso, recebe uma visão cuidadosamente filtrada e namespaced do mesmo kernel que o host usa. Como resultado, containers costumam ser mais leves, mais rápidos para iniciar, mais fáceis de colocar densamente em uma máquina e mais adequados para deploys de aplicações de curta duração. O preço é que o boundary de isolamento depende muito mais diretamente da configuração correta do host e do runtime.

Isso não significa que containers sejam "inseguros" e VMs sejam "seguros". Significa que o modelo de segurança é diferente. Um stack de containers bem configurado com rootless execution, user namespaces, seccomp padrão, um conjunto estrito de capabilities, sem compartilhamento de host namespaces e forte enforcement de SELinux ou AppArmor pode ser muito robusto. Por outro lado, um container iniciado com `--privileged`, compartilhamento de PID/network com o host, o Docker socket montado dentro dele e um bind mount gravável de `/` está funcionalmente muito mais próximo de acesso root no host do que de uma sandbox de aplicação isolada de forma segura. A diferença vem das camadas que foram habilitadas ou desabilitadas.

Há também um meio termo que os leitores devem entender porque aparece cada vez mais em ambientes reais. Runtimes de containers sandboxed tais como gVisor e Kata Containers intencionalmente endurecem o boundary além de um container clássico `runc`. gVisor coloca uma camada de kernel em userspace entre a workload e muitas interfaces do kernel do host, enquanto Kata lança a workload dentro de uma virtual machine leve. Estes ainda são usados através de ecossistemas de containers e fluxos de orquestração, mas suas propriedades de segurança diferem de runtimes OCI simples e não devem ser mentalmente agrupados com "normal Docker containers" como se tudo se comportasse da mesma forma.

## O Stack de Containers: Várias Camadas, Não Uma Só

Quando alguém diz "este container é inseguro", a pergunta de acompanhamento útil é: **qual camada o tornou inseguro?** Uma workload containerizada é geralmente o resultado de vários componentes trabalhando juntos.

No topo, frequentemente existe uma **image build layer** como BuildKit, Buildah ou Kaniko, que cria a imagem OCI e seus metadados. Acima do runtime de baixo nível, pode haver um **engine ou manager** como Docker Engine, Podman, containerd, CRI-O, Incus ou systemd-nspawn. Em ambientes de cluster, também pode haver um **orchestrator** como Kubernetes decidindo a postura de segurança requisitada através da configuração da workload. Finalmente, o **kernel** é o que realmente aplica namespaces, cgroups, seccomp e políticas MAC.

Esse modelo em camadas é importante para entender defaults. Uma restrição pode ser solicitada pelo Kubernetes, traduzida via CRI pelo containerd ou CRI-O, convertida em um spec OCI pelo wrapper do runtime, e só então aplicada por `runc`, `crun`, `runsc` ou outro runtime contra o kernel. Quando defaults diferem entre ambientes, frequentemente é porque uma dessas camadas mudou a configuração final. O mesmo mecanismo pode, portanto, aparecer no Docker ou Podman como uma flag de CLI, no Kubernetes como um Pod ou campo `securityContext`, e em stacks de runtime de baixo nível como configuração OCI gerada para a workload. Por essa razão, exemplos de CLI nesta seção devem ser lidos como **sintaxe específica do runtime para um conceito geral de container**, não como flags universais suportadas por toda ferramenta.

## O Verdadeiro Boundary de Segurança do Container

Na prática, segurança de containers vem de **controles sobrepostos**, não de um único controle perfeito. Namespaces isolam visibilidade. cgroups governam e limitam uso de recursos. Capabilities reduzem o que um processo com aparência privilegiada pode realmente fazer. seccomp bloqueia syscalls perigosos antes que alcancem o kernel. AppArmor e SELinux adicionam Mandatory Access Control além das checagens DAC normais. `no_new_privs`, caminhos procfs mascarados e caminhos do sistema somente leitura tornam cadeias comuns de abuso de privilégios e de proc/sys mais difíceis. O próprio runtime também importa porque decide como mounts, sockets, labels e joins de namespace são criados.

É por isso que muita documentação sobre segurança de containers parece repetitiva. A mesma cadeia de escape frequentemente depende de múltiplos mecanismos ao mesmo tempo. Por exemplo, um bind mount gravável do host é ruim, mas torna-se muito pior se o container também executa como root real no host, possui `CAP_SYS_ADMIN`, não é confinado por seccomp e não é restringido por SELinux ou AppArmor. Do mesmo modo, compartilhamento de PID com o host é uma exposição séria, mas torna-se dramaticamente mais útil para um atacante quando combinado com `CAP_SYS_PTRACE`, proteções fracas em procfs ou ferramentas de entrada em namespace como `nsenter`. A forma correta de documentar o tópico é, portanto, não repetindo o mesmo ataque em cada página, mas explicando o que cada camada contribui para o boundary final.

## Como Ler Esta Seção

A seção está organizada dos conceitos mais gerais para os mais específicos.

Comece com a visão geral do runtime e ecossistema:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Depois revise os planos de controle e superfícies da supply-chain que frequentemente decidem se um atacante sequer precisa de um kernel escape:

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

Então passe para o modelo de proteção:

{{#ref}}
protections/
{{#endref}}

As páginas de namespaces explicam as primitives de isolamento do kernel individualmente:

{{#ref}}
protections/namespaces/
{{#endref}}

As páginas sobre cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, caminhos mascarados e caminhos do sistema somente leitura explicam os mecanismos que normalmente são empilhados sobre namespaces:

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

## Uma Boa Mentalidade Inicial de Enumeração

Ao avaliar um alvo containerizado, é muito mais útil fazer um pequeno conjunto de perguntas técnicas precisas do que pular imediatamente para PoCs famosos de escape. Primeiro, identifique o **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer ou algo mais especializado. Depois identifique o **runtime**: `runc`, `crun`, `runsc`, `kata-runtime` ou outra implementação compatível OCI. Em seguida, verifique se o ambiente é **rootful ou rootless**, se **user namespaces** estão ativos, se algum **host namespace** é compartilhado, quais **capabilities** permanecem, se **seccomp** está habilitado, se uma **MAC policy** está realmente aplicando, se **mounts ou sockets perigosos** estão presentes e se o processo pode interagir com a API do container runtime.

Essas respostas dizem muito mais sobre a postura real de segurança do que o nome da imagem base jamais dirá. Em muitas avaliações, você pode prever a família provável de breakout antes de ler um único arquivo da aplicação apenas entendendo a configuração final do container.

## Cobertura

Esta seção cobre o material antigo focado em Docker sob uma organização orientada a containers: runtime e exposição do daemon, authorization plugins, trust de imagem e build secrets, mounts sensíveis do host, workloads distroless, containers privilegiados e as proteções do kernel normalmente empilhadas ao redor da execução de containers.
{{#include ../../../banners/hacktricks-training.md}}
