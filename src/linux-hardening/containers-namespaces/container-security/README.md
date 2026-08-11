# Segurança de Contêineres

## O Que Um Contêiner Realmente É

Uma forma prática de definir um contêiner é esta: um contêiner é uma **árvore regular de processos Linux** iniciada sob uma configuração específica no estilo OCI, de modo que ela veja um sistema de arquivos controlado, um conjunto controlado de recursos do kernel e um modelo de privilégios restrito. O processo pode acreditar que é o PID 1, pode acreditar que tem sua própria pilha de rede, pode acreditar que possui seu próprio hostname e recursos de IPC e pode até ser executado como root dentro do próprio user namespace. Porém, por baixo de tudo, ele ainda é um processo do host que o kernel agenda como qualquer outro.

É por isso que a segurança de contêineres consiste, na prática, em estudar como essa ilusão é construída e como ela falha. Se o mount namespace for fraco, o processo poderá ver o sistema de arquivos do host. Se o user namespace estiver ausente ou desabilitado, o root dentro do contêiner poderá ser mapeado muito diretamente para o root no host. Se o seccomp estiver unconfined e o conjunto de capabilities for amplo demais, o processo poderá acessar syscalls e recursos privilegiados do kernel que deveriam permanecer inacessíveis. Se o runtime socket estiver montado dentro do contêiner, talvez o contêiner nem precise de um kernel breakout, pois poderá simplesmente solicitar ao runtime que inicie um contêiner irmão mais poderoso ou monte diretamente o sistema de arquivos root do host.

## Como os Contêineres Diferem das Virtual Machines

Uma VM normalmente contém seu próprio kernel e uma camada de abstração de hardware. Isso significa que o kernel guest pode falhar, entrar em panic ou ser explorado sem implicar automaticamente controle direto sobre o kernel do host. Em contêineres, a workload não recebe um kernel separado. Em vez disso, ela recebe uma visão cuidadosamente filtrada e organizada em namespaces do mesmo kernel usado pelo host. Como resultado, os contêineres normalmente são mais leves, iniciam mais rapidamente, são mais fáceis de alocar densamente em uma máquina e são mais adequados à implantação de aplicações de curta duração. O preço é que a camada de isolamento depende muito mais diretamente da configuração correta do host e do runtime.

Isso não significa que contêineres sejam "inseguros" e VMs sejam "seguras". Significa que o modelo de segurança é diferente. Uma stack de contêineres bem configurada, com execução rootless, user namespaces, seccomp padrão, um conjunto estrito de capabilities, nenhum compartilhamento de host namespaces e aplicação forte de SELinux ou AppArmor, pode ser muito robusta. Por outro lado, um contêiner iniciado com `--privileged`, compartilhamento do PID/network do host, Docker socket montado dentro dele e um bind mount gravável de `/` fica funcionalmente muito mais próximo de um acesso root ao host do que de um application sandbox isolado com segurança. A diferença vem das camadas que foram habilitadas ou desabilitadas.

Também existe um meio-termo que os leitores devem compreender, pois ele aparece cada vez mais em ambientes reais. **Sandboxed container runtimes**, como **gVisor** e **Kata Containers**, reforçam intencionalmente a camada de isolamento além de um contêiner `runc` clássico. O gVisor coloca uma camada de kernel em userspace entre a workload e muitas interfaces do kernel do host, enquanto o Kata inicia a workload dentro de uma virtual machine leve. Eles ainda são usados por meio de ecossistemas de contêineres e workflows de orquestração, mas suas propriedades de segurança diferem das de runtimes OCI comuns e não devem ser mentalmente agrupados com "contêineres Docker normais", como se tudo se comportasse da mesma forma.

## A Stack de Contêineres: Várias Camadas, Não Uma Só

Quando alguém diz "este contêiner é inseguro", a pergunta útil seguinte é: **qual camada o tornou inseguro?** Uma workload conteinerizada normalmente é o resultado do trabalho conjunto de vários componentes.

No topo, frequentemente há uma **camada de build de imagens**, como BuildKit, Buildah ou Kaniko, que cria a imagem OCI e os metadados. Acima do runtime de baixo nível, pode haver um **engine ou manager**, como Docker Engine, Podman, containerd, CRI-O, Incus ou systemd-nspawn. Em ambientes de cluster, também pode haver um **orchestrator**, como Kubernetes, decidindo a postura de segurança solicitada por meio da configuração da workload. Por fim, o **kernel** é o que realmente aplica namespaces, cgroups, seccomp e a política MAC.

Esse modelo em camadas é importante para compreender os padrões. Uma restrição pode ser solicitada pelo Kubernetes, traduzida por meio do CRI pelo containerd ou CRI-O, convertida em uma OCI spec pelo runtime wrapper e só então aplicada pelo `runc`, `crun`, `runsc` ou outro runtime contra o kernel. Quando os padrões diferem entre ambientes, isso geralmente ocorre porque uma dessas camadas alterou a configuração final. O mesmo mecanismo pode aparecer no Docker ou Podman como uma opção de CLI, no Kubernetes como um campo de Pod ou `securityContext` e, em stacks de runtimes de nível inferior, como uma configuração OCI gerada para a workload. Por esse motivo, os exemplos de CLI nesta seção devem ser lidos como **sintaxe específica de runtime para um conceito geral de contêiner**, e não como flags universais compatíveis com todas as ferramentas.

## A Verdadeira Camada de Segurança dos Contêineres

Na prática, a segurança de contêineres vem de **controles sobrepostos**, não de um único controle perfeito. Namespaces isolam a visibilidade. cgroups governam e limitam o uso de recursos. Capabilities reduzem o que um processo aparentemente privilegiado pode realmente fazer. seccomp bloqueia syscalls perigosas antes que elas cheguem ao kernel. AppArmor e SELinux adicionam Mandatory Access Control sobre as verificações DAC normais. `no_new_privs`, caminhos de procfs mascarados e caminhos de sistema somente leitura dificultam cadeias comuns de abuso de privilégios e de proc/sys. O próprio runtime também importa, pois decide como mounts, sockets, labels e joins de namespaces são criados.

É por isso que grande parte da documentação de segurança de contêineres parece repetitiva. A mesma cadeia de escape frequentemente depende de vários mecanismos ao mesmo tempo. Por exemplo, um host bind mount gravável é ruim, mas se torna muito pior se o contêiner também for executado como root real no host, tiver `CAP_SYS_ADMIN`, estiver unconfined pelo seccomp e não for restrito pelo SELinux ou AppArmor. Da mesma forma, o compartilhamento do PID do host é uma exposição séria, mas se torna muito mais útil para um atacante quando combinado com `CAP_SYS_PTRACE`, proteções fracas de procfs ou ferramentas de entrada em namespaces, como `nsenter`. Portanto, a forma correta de documentar o tema não é repetir o mesmo ataque em todas as páginas, mas explicar o que cada camada contribui para a camada de segurança final.

## Como Ler Esta Seção

A seção está organizada dos conceitos mais gerais aos mais específicos.

Comece pela visão geral de runtimes e ecossistemas:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Em seguida, revise os control planes e as superfícies de supply chain que frequentemente determinam se um atacante sequer precisa de um kernel escape:

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

As páginas sobre cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, caminhos mascarados e caminhos de sistema somente leitura explicam os mecanismos normalmente aplicados sobre os namespaces:

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

Ao avaliar um alvo conteinerizado, é muito mais útil fazer um pequeno conjunto de perguntas técnicas precisas do que começar imediatamente por PoCs famosas de escape. Primeiro, identifique a **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer ou algo mais especializado. Depois, identifique o **runtime**: `runc`, `crun`, `runsc`, `kata-runtime` ou outra implementação compatível com OCI. Em seguida, verifique se o ambiente é **rootful ou rootless**, se os **user namespaces** estão ativos, se algum **host namespace** é compartilhado, quais **capabilities** permanecem, se o **seccomp** está habilitado, se uma **política MAC** está realmente sendo aplicada, se **mounts ou sockets perigosos** estão presentes e se o processo pode interagir com a API do container runtime.

Essas respostas informam muito mais sobre a postura de segurança real do que o nome da base image. Em muitas avaliações, é possível prever a provável família de breakout antes de ler um único arquivo da aplicação, apenas compreendendo a configuração final do contêiner.

## Cobertura

Esta seção aborda o conteúdo antigo, focado no Docker, sob uma organização orientada a contêineres: exposição de runtime e daemon, authorization plugins, confiança em imagens e build secrets, mounts sensíveis do host, workloads distroless, contêineres privilegiados e as proteções do kernel normalmente aplicadas à execução de contêineres.

{{#include ../../../banners/hacktricks-training.md}}
