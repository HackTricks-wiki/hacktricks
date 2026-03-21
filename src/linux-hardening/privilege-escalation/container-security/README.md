# Container Security

{{#include ../../../banners/hacktricks-training.md}}

## What A Container Actually Is

Uma forma prática de definir um container é esta: um container é uma **árvore de processos Linux regular** que foi iniciada sob uma configuração estilo OCI específica de modo que vê um filesystem controlado, um conjunto controlado de recursos do kernel e um modelo de privilégios restrito. O processo pode acreditar que é PID 1, pode acreditar que tem sua própria pilha de rede, pode acreditar que possui seu próprio hostname e recursos de IPC, e pode até executar como root dentro de seu próprio user namespace. Mas por baixo do capô continua sendo um processo do host que o kernel agenda como qualquer outro.

É por isso que container security é realmente o estudo de como essa ilusão é construída e como ela falha. Se o mount namespace for fraco, o processo pode ver o filesystem do host. Se o user namespace estiver ausente ou desabilitado, root dentro do container pode mapear-se muito de perto ao root no host. Se seccomp estiver sem confinamento e o conjunto de capabilities for muito amplo, o processo pode alcançar syscalls e funcionalidades privilegiadas do kernel que deveriam permanecer fora de alcance. Se o runtime socket estiver montado dentro do container, o container pode não precisar de um kernel breakout de todo porque pode simplesmente pedir ao runtime para lançar um container irmão mais poderoso ou montar diretamente o host root filesystem.

## How Containers Differ From Virtual Machines

Uma VM normalmente carrega seu próprio kernel e fronteira de abstração de hardware. Isso significa que o kernel convidado pode travar, entrar em panic ou ser explorado sem implicar automaticamente controle direto do kernel do host. Em containers, a carga de trabalho não recebe um kernel separado. Em vez disso, recebe uma visão cuidadosamente filtrada e namespaced do mesmo kernel que o host usa. Como resultado, containers são geralmente mais leves, mais rápidos para iniciar, mais fáceis de empacotar densamente em uma máquina e mais adequados para deployment de aplicações de curta duração. O preço é que a fronteira de isolamento depende muito mais diretamente da configuração correta do host e do runtime.

Isso não quer dizer que containers sejam "inseguros" e VMs sejam "seguras". Significa que o modelo de segurança é diferente. Uma pilha de container bem configurada com execução rootless, user namespaces, seccomp padrão, um conjunto estrito de capabilities, sem compartilhamento de namespaces do host e forte aplicação de SELinux ou AppArmor pode ser muito robusta. Pelo contrário, um container iniciado com `--privileged`, compartilhamento de PID/rede do host, o Docker socket montado dentro dele e um bind mount gravável de `/` é funcionalmente muito mais próximo do acesso root no host do que de um sandbox de aplicação isolado com segurança. A diferença vem das camadas que foram habilitadas ou desabilitadas.

Há também um terreno intermediário que os leitores devem entender porque aparece cada vez mais em ambientes reais. **Sandboxed container runtimes** tais como **gVisor** e **Kata Containers** intencionalmente endurecem a fronteira além de um container clássico `runc`. gVisor coloca uma camada de kernel em userspace entre a carga de trabalho e muitas interfaces do kernel do host, enquanto Kata lança a carga de trabalho dentro de uma máquina virtual leve. Estes ainda são usados através de ecossistemas de container e fluxos de orquestração, mas suas propriedades de segurança diferem dos runtimes OCI simples e não devem ser mentalmente agrupados com "normal Docker containers" como se tudo se comportasse da mesma forma.

## The Container Stack: Several Layers, Not One

Quando alguém diz "this container is insecure", a pergunta de seguimento útil é: **qual camada o tornou inseguro?** Uma carga de trabalho containerizada é geralmente o resultado de vários componentes trabalhando juntos.

No topo, muitas vezes há uma **image build layer** como BuildKit, Buildah, ou Kaniko, que cria a imagem OCI e metadados. Abaixo do runtime de baixo nível, pode haver um **engine or manager** como Docker Engine, Podman, containerd, CRI-O, Incus, ou systemd-nspawn. Em ambientes de cluster, também pode haver um **orchestrator** como Kubernetes decidindo a postura de segurança solicitada através da configuração da carga de trabalho. Finalmente, o **kernel** é o que realmente impõe namespaces, cgroups, seccomp e política MAC.

Esse modelo em camadas é importante para entender defaults. Uma restrição pode ser solicitada pelo Kubernetes, traduzida através do CRI pelo containerd ou CRI-O, convertida em um OCI spec pelo runtime wrapper, e só então aplicada por `runc`, `crun`, `runsc`, ou outro runtime contra o kernel. Quando defaults diferem entre ambientes, frequentemente é porque uma dessas camadas mudou a configuração final. O mesmo mecanismo pode, portanto, aparecer no Docker ou Podman como uma flag de CLI, no Kubernetes como um Pod ou campo `securityContext`, e em pilhas de runtime de nível inferior como configuração OCI gerada para a carga de trabalho. Por essa razão, exemplos de CLI nesta seção devem ser lidos como **sintaxe específica do runtime para um conceito geral de container**, não como flags universais suportadas por toda ferramenta.

## The Real Container Security Boundary

Na prática, container security vem de **controles sobrepostos**, não de um único controle perfeito. Namespaces isolam visibilidade. cgroups governam e limitam uso de recursos. Capabilities reduzem o que um processo com aparência privilegiada pode realmente fazer. seccomp bloqueia syscalls perigosos antes de alcançarem o kernel. AppArmor e SELinux adicionam Mandatory Access Control além das checagens DAC normais. `no_new_privs`, caminhos procfs mascarados, e paths do sistema em read-only tornam cadeias comuns de abuso de privilégios e proc/sys mais difíceis. O runtime em si também importa porque decide como mounts, sockets, labels e joins de namespace são criados.

É por isso que muita documentação de container security parece repetitiva. A mesma escape chain frequentemente depende de múltiplos mecanismos ao mesmo tempo. Por exemplo, um host bind mount gravável é ruim, mas torna-se muito pior se o container também roda como root real no host, tem `CAP_SYS_ADMIN`, está sem confinamento por seccomp, e não é restringido por SELinux ou AppArmor. Igualmente, o compartilhamento de PID do host é uma exposição séria, mas torna-se dramaticamente mais útil para um atacante quando combinado com `CAP_SYS_PTRACE`, proteções fracas em procfs, ou ferramentas de entrada em namespace como `nsenter`. A maneira correta de documentar o tópico é portanto não repetir o mesmo ataque em cada página, mas explicar o que cada camada contribui para a fronteira final.

## How To Read This Section

A seção está organizada dos conceitos mais gerais para os mais específicos.

Comece com o overview do runtime e ecossistema:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Em seguida revise os control planes e superfícies da supply-chain que frequentemente decidem se um atacante precisa mesmo de um kernel escape:

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

Depois passe para o modelo de proteção:

{{#ref}}
protections/
{{#endref}}

As páginas de namespace explicam os primitivos de isolamento do kernel individualmente:

{{#ref}}
protections/namespaces/
{{#endref}}

As páginas sobre cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths, e read-only system paths explicam os mecanismos que geralmente são empilhados sobre namespaces:

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

## A Good First Enumeration Mindset

Ao avaliar um alvo containerizado, é muito mais útil fazer um pequeno conjunto de perguntas técnicas precisas do que pular imediatamente para famosos escape PoCs. Primeiro, identifique a **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer, ou algo mais especializado. Depois identifique o **runtime**: `runc`, `crun`, `runsc`, `kata-runtime`, ou outra implementação compatível com OCI. Depois disso, verifique se o ambiente é **rootful ou rootless**, se **user namespaces** estão ativos, se algum **host namespace** está compartilhado, quais **capabilities** permanecem, se **seccomp** está habilitado, se uma **MAC policy** está realmente aplicando, se **mounts ou sockets perigosos** estão presentes, e se o processo pode interagir com a container runtime API.

Essas respostas dizem muito mais sobre a postura real de segurança do que o nome da imagem base jamais dirá. Em muitas avaliações, você pode prever a família provável de breakout antes de ler um único arquivo de aplicação apenas entendendo a configuração final do container.

## Coverage

Esta seção cobre o material antigo focado em Docker sob organização orientada a container: runtime e exposição do daemon, authorization plugins, confiança de imagem e build secrets, sensitive host mounts, distroless workloads, privileged containers, e as proteções do kernel normalmente empilhadas em torno da execução de containers.
