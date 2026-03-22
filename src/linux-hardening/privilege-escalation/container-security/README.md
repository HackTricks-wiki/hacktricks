# Segurança de Contêineres

{{#include ../../../banners/hacktricks-training.md}}

## O que um contêiner realmente é

Uma forma prática de definir um contêiner é esta: um contêiner é uma **árvore de processos Linux regular** que foi iniciada sob uma configuração específica no estilo OCI de modo que vê um sistema de arquivos controlado, um conjunto controlado de recursos do kernel e um modelo de privilégios restrito. O processo pode acreditar que é PID 1, pode acreditar que tem sua própria pilha de rede, pode acreditar que possui seu próprio nome do host e recursos IPC, e pode até executar como root dentro do seu próprio user namespace. Mas por baixo do capô continua sendo um processo do host que o kernel agenda como qualquer outro.

Por isso a segurança de contêineres é, na prática, o estudo de como essa ilusão é construída e como ela falha. Se o mount namespace for fraco, o processo pode ver o filesystem do host. Se o user namespace estiver ausente ou desativado, o root dentro do contêiner pode mapear de forma muito próxima ao root do host. Se o seccomp estiver sem restrições e o conjunto de capabilities for amplo demais, o processo pode alcançar syscalls e funcionalidades privilegiadas do kernel que deveriam permanecer fora de alcance. Se o runtime socket estiver montado dentro do contêiner, talvez o contêiner nem precise quebrar o kernel, porque pode simplesmente pedir ao runtime para lançar um contêiner irmão mais poderoso ou montar diretamente o filesystem raiz do host.

## Como contêineres diferem de máquinas virtuais

Uma VM normalmente carrega seu próprio kernel e uma fronteira de abstração de hardware. Isso significa que o kernel guest pode travar, entrar em panic, ou ser explorado sem implicar automaticamente controle direto do kernel do host. Em contêineres, a carga de trabalho não recebe um kernel separado. Em vez disso, recebe uma visão cuidadosamente filtrada e namespaced do mesmo kernel que o host usa. Como resultado, contêineres costumam ser mais leves, mais rápidos para iniciar, mais fáceis de alocar densamente em uma máquina e melhor adequados para deploys de aplicações de curta duração. O preço é que a fronteira de isolamento depende muito mais diretamente da configuração correta do host e do runtime.

Isso não significa que contêineres sejam "inseguros" e VMs sejam "seguros". Significa que o modelo de segurança é diferente. Um stack de contêiner bem configurado com execução rootless, user namespaces, seccomp padrão, um conjunto estrito de capabilities, sem compartilhamento de namespaces do host e forte aplicação de SELinux ou AppArmor pode ser muito robusto. Por outro lado, um contêiner iniciado com `--privileged`, compartilhamento de PID/rede com o host, o Docker socket montado dentro dele e um bind mount gravável de `/` é funcionalmente muito mais próximo do acesso root do host do que de um sandbox de aplicação isolado com segurança. A diferença vem das camadas que foram habilitadas ou desabilitadas.

Há também um terreno intermediário que os leitores devem entender porque aparece cada vez mais em ambientes reais. Runtimes de contêiner sandboxed como gVisor e Kata Containers endurecem intencionalmente a fronteira além de um contêiner clássico `runc`. gVisor coloca uma camada de kernel em espaço de usuário entre a carga de trabalho e muitas interfaces do kernel do host, enquanto Kata executa a carga de trabalho dentro de uma máquina virtual leve. Eles ainda são usados através dos ecossistemas de contêiner e fluxos de orquestração, mas suas propriedades de segurança diferem dos runtimes OCI simples e não devem ser mentalmente agrupados com "normal Docker containers" como se tudo se comportasse da mesma forma.

## A pilha de contêiner: várias camadas, não uma só

Quando alguém diz "este contêiner é inseguro", a pergunta útil de seguimento é: **qual camada o tornou inseguro?** Uma carga de trabalho containerizada é normalmente o resultado de vários componentes trabalhando juntos.

No topo, muitas vezes existe uma **camada de build de imagem** como BuildKit, Buildah ou Kaniko, que cria a imagem OCI e os metadados. Acima do runtime de baixo nível, pode haver um **engine ou manager** como Docker Engine, Podman, containerd, CRI-O, Incus ou systemd-nspawn. Em ambientes de cluster, também pode haver um **orquestrador** como Kubernetes decidindo a postura de segurança solicitada através da configuração da carga de trabalho. Finalmente, o **kernel** é o que realmente aplica namespaces, cgroups, seccomp e políticas MAC.

Este modelo em camadas é importante para entender os padrões padrão. Uma restrição pode ser solicitada pelo Kubernetes, traduzida via CRI por containerd ou CRI-O, convertida em um spec OCI pelo wrapper do runtime e só então aplicada pelo `runc`, `crun`, `runsc` ou outro runtime contra o kernel. Quando os padrões diferem entre ambientes, frequentemente é porque uma dessas camadas alterou a configuração final. O mesmo mecanismo pode, portanto, aparecer no Docker ou Podman como uma flag de CLI, no Kubernetes como um campo Pod ou `securityContext`, e em stacks de runtime de nível mais baixo como uma configuração OCI gerada para a carga de trabalho. Por essa razão, exemplos de CLI nesta seção devem ser lidos como **sintaxe específica do runtime para um conceito geral de contêiner**, não como flags universais suportadas por toda ferramenta.

## A verdadeira fronteira de segurança do contêiner

Na prática, a segurança de contêiner vem de **controles sobrepostos**, não de um único controle perfeito. Namespaces isolam visibilidade. cgroups regem e limitam o uso de recursos. Capabilities reduzem o que um processo com aparência privilegiada pode realmente fazer. seccomp bloqueia syscalls perigosas antes que alcancem o kernel. AppArmor e SELinux adicionam Mandatory Access Control por cima das checagens DAC normais. `no_new_privs`, caminhos procfs mascarados e caminhos do sistema somente leitura tornam correntes comuns de abuso de privilégio e proc/sys mais difíceis. O próprio runtime também importa porque decide como mounts, sockets, labels e entradas em namespaces são criados.

É por isso que muita documentação sobre segurança de contêiner parece repetitiva. A mesma cadeia de escape frequentemente depende de múltiplos mecanismos ao mesmo tempo. Por exemplo, um bind mount de host gravável é ruim, mas fica muito pior se o contêiner também roda como root real no host, tem `CAP_SYS_ADMIN`, está sem confinamento de seccomp e não é restringido por SELinux ou AppArmor. Da mesma forma, o compartilhamento de PID do host é uma exposição séria, mas torna-se dramaticamente mais útil para um atacante quando é combinado com `CAP_SYS_PTRACE`, proteções fracas em procfs ou ferramentas de entrada em namespaces como `nsenter`. A maneira correta de documentar o tema não é repetir o mesmo ataque em cada página, mas explicar o que cada camada contribui para a fronteira final.

## Como ler esta seção

A seção está organizada dos conceitos mais gerais para os mais específicos.

Comece com a visão geral do runtime e do ecossistema:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Depois revise os planos de controle e as superfícies da supply-chain que frequentemente decidem se um atacante precisa ou não de um escape de kernel:

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

Depois avance para o modelo de proteção:

{{#ref}}
protections/
{{#endref}}

As páginas sobre namespaces explicam os primitivos de isolamento do kernel individualmente:

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

## Uma boa mentalidade inicial para enumeração

Ao avaliar um alvo containerizado, é muito mais útil fazer um pequeno conjunto de perguntas técnicas precisas do que pular imediatamente para PoCs famosos de escape. Primeiro, identifique o **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer ou algo mais especializado. Em seguida identifique o **runtime**: `runc`, `crun`, `runsc`, `kata-runtime` ou outra implementação compatível com OCI. Depois disso, verifique se o ambiente é **rootful ou rootless**, se **user namespaces** estão ativos, se algum **host namespace** é compartilhado, quais **capabilities** permanecem, se **seccomp** está habilitado, se uma **política MAC** está realmente fazendo aplicação, se **mounts ou sockets perigosos** estão presentes e se o processo pode interagir com a API do container runtime.

Essas respostas dizem muito mais sobre a postura real de segurança do que o nome da imagem base jamais dirá. Em muitas avaliações, você pode prever a família provável de breakout antes de ler um único arquivo de aplicação apenas entendendo a configuração final do contêiner.

## Cobertura

Esta seção cobre o material antigo focado em Docker sob organização orientada a contêiner: exposição de runtime e daemon, authorization plugins, confiança de imagem e secrets de build, mounts sensíveis do host, workloads distroless, contêineres privilegiados e as proteções de kernel normalmente empilhadas em torno da execução de contêiner.
{{#include ../../../banners/hacktricks-training.md}}
