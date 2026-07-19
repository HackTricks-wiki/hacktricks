# Runtimes, Engines, Builders E Sandboxes De Containers

{{#include ../../../banners/hacktricks-training.md}}

Uma das maiores fontes de confusão em container security é que vários componentes completamente diferentes costumam ser agrupados sob a mesma palavra. "Docker" pode se referir a um formato de imagem, uma CLI, um daemon, um sistema de build, uma stack de runtime ou simplesmente à ideia de containers em geral. Para trabalhos de security, essa ambiguidade é um problema, porque diferentes camadas são responsáveis por diferentes proteções. Um breakout causado por um bind mount incorreto não é a mesma coisa que um breakout causado por um bug no runtime de baixo nível, e nenhum dos dois é igual a um erro de política de cluster no Kubernetes.

Esta página separa o ecossistema por função para que o restante da seção possa explicar com precisão onde uma proteção ou fraqueza realmente está localizada.

## OCI Como Linguagem Comum

As stacks modernas de containers Linux geralmente interoperam porque falam um conjunto de especificações OCI. A **OCI Image Specification** descreve como imagens e layers são representadas. A **OCI Runtime Specification** descreve como o runtime deve iniciar o processo, incluindo namespaces, mounts, cgroups e configurações de security. A **OCI Distribution Specification** padroniza como os registries expõem conteúdo.

Isso é importante porque explica por que uma container image criada com uma ferramenta pode frequentemente ser executada com outra, e por que vários engines podem compartilhar o mesmo runtime de baixo nível. Também explica por que o comportamento de security pode parecer semelhante em diferentes produtos: muitos deles estão construindo a mesma configuração de runtime OCI e entregando-a ao mesmo pequeno conjunto de runtimes.

## OCI Runtimes De Baixo Nível

O runtime de baixo nível é o componente mais próximo da fronteira com o kernel. É a parte que realmente cria namespaces, grava configurações de cgroup, aplica capabilities e filtros seccomp e, por fim, executa `execve()` no processo do container. Quando as pessoas discutem "isolamento de containers" no nível mecânico, geralmente estão falando desta camada, mesmo que não o digam explicitamente.

### `runc`

`runc` é o runtime OCI de referência e continua sendo a implementação mais conhecida. Ele é amplamente usado pelo Docker, containerd e por muitas deployments de Kubernetes. Grande parte das pesquisas públicas e do material de exploitation tem como alvo ambientes no estilo `runc`, simplesmente porque eles são comuns e porque `runc` define a baseline que muitas pessoas imaginam quando pensam em um container Linux. Portanto, entender o `runc` fornece ao leitor um modelo mental sólido para o isolamento clássico de containers.

### `crun`

`crun` é outro runtime OCI, escrito em C e amplamente usado em ambientes modernos do Podman. Ele costuma ser elogiado pelo bom suporte a cgroup v2, pela boa ergonomia rootless e pelo menor overhead. Do ponto de vista de security, o importante não é ele ser escrito em uma linguagem diferente, mas continuar desempenhando a mesma função: é o componente que transforma a configuração OCI em uma árvore de processos em execução sob o kernel. Um workflow rootless do Podman frequentemente acaba parecendo mais seguro não porque `crun` corrija tudo magicamente, mas porque a stack geral ao seu redor tende a adotar mais fortemente user namespaces e least privilege.

### `runsc` Do gVisor

`runsc` é o runtime usado pelo gVisor. Aqui, a fronteira muda de forma significativa. Em vez de passar a maioria dos syscalls diretamente ao kernel do host da maneira usual, o gVisor insere uma camada de kernel em userspace que emula ou intermedeia grande parte da interface Linux. O resultado não é um container `runc` normal com algumas flags adicionais; é um design de sandbox diferente, cujo objetivo é reduzir a attack surface do kernel do host. Tradeoffs de compatibilidade e performance fazem parte desse design, portanto ambientes que usam `runsc` devem ser documentados de forma diferente dos ambientes normais de runtime OCI.

### `kata-runtime`

Kata Containers levam a fronteira ainda mais longe ao iniciar o workload dentro de uma lightweight virtual machine. Administrativamente, isso ainda pode parecer uma deployment de containers, e as camadas de orchestration ainda podem tratá-la dessa forma, mas a fronteira de isolamento subjacente é mais próxima da virtualization do que de um container clássico que compartilha o kernel do host. Isso torna o Kata útil quando se deseja um isolamento de tenant mais forte sem abandonar workflows centrados em containers.

## Engines E Container Managers

Se o runtime de baixo nível é o componente que conversa diretamente com o kernel, o engine ou manager é o componente com o qual usuários e operadores normalmente interagem. Ele gerencia image pulls, metadata, logs, networks, volumes, operações de lifecycle e exposição de APIs. Essa camada é extremamente importante porque muitos compromissos reais acontecem aqui: acesso a um runtime socket ou à daemon API pode ser equivalente a um host compromise, mesmo que o runtime de baixo nível esteja perfeitamente saudável.

### Docker Engine

Docker Engine é a plataforma de containers mais reconhecida entre developers e uma das razões pelas quais o vocabulário de containers assumiu uma forma tão associada ao Docker. O caminho típico é a CLI `docker` até o `dockerd`, que, por sua vez, coordena componentes de nível inferior, como `containerd` e um runtime OCI. Historicamente, as deployments Docker frequentemente têm sido **rootful**, e o acesso ao Docker socket consequentemente se tornou um primitive muito poderoso. É por isso que tanto material prático de privilege escalation se concentra em `docker.sock`: se um processo pode solicitar ao `dockerd` a criação de um container privilegiado, montar paths do host ou ingressar em host namespaces, talvez não precise de um kernel exploit.

### Podman

O Podman foi projetado em torno de um modelo mais daemonless. Operacionalmente, isso ajuda a reforçar a ideia de que containers são apenas processos gerenciados por mecanismos Linux padrão, em vez de serem gerenciados por um daemon privilegiado de longa duração. O Podman também possui uma história **rootless** muito mais forte do que as deployments clássicas do Docker que muitas pessoas conheceram primeiro. Isso não torna o Podman automaticamente seguro, mas altera significativamente o risk profile padrão, especialmente quando combinado com user namespaces, SELinux e `crun`.

### containerd

containerd é um componente central de gerenciamento de runtimes em muitas stacks modernas. Ele é usado pelo Docker e também é um dos backends de runtime dominantes do Kubernetes. Ele expõe APIs poderosas, gerencia images e snapshots e delega a criação final do processo a um runtime de baixo nível. As discussões de security sobre containerd devem enfatizar que o acesso ao containerd socket ou às funcionalidades de `ctr`/`nerdctl` pode ser tão perigoso quanto o acesso à API do Docker, mesmo que a interface e o workflow pareçam menos "developer friendly".

### CRI-O

CRI-O é mais focado do que o Docker Engine. Em vez de ser uma plataforma de uso geral para developers, ele foi desenvolvido para implementar de forma limpa o Kubernetes Container Runtime Interface. Isso o torna especialmente comum em distribuições Kubernetes e em ecossistemas fortemente baseados em SELinux, como o OpenShift. Do ponto de vista de security, esse escopo mais restrito é útil porque reduz a desordem conceitual: o CRI-O faz claramente parte da camada "executar containers para Kubernetes", e não de uma plataforma que faz tudo.

### Incus, LXD E LXC

Sistemas Incus/LXD/LXC merecem ser separados dos application containers no estilo Docker porque costumam ser usados como **system containers**. Normalmente, espera-se que um system container se pareça mais com uma máquina lightweight, com um userspace mais completo, serviços de longa duração, maior exposição de devices e integração mais ampla com o host. Os mecanismos de isolamento ainda são primitives do kernel, mas as expectativas operacionais são diferentes. Como resultado, as misconfigurations aqui frequentemente se parecem menos com "defaults ruins de app-container" e mais com erros de lightweight virtualization ou de delegação ao host.

### systemd-nspawn

systemd-nspawn ocupa uma posição interessante porque é nativo do systemd e muito útil para testing, debugging e execução de ambientes semelhantes a sistemas operacionais. Ele não é o runtime de produção cloud-native dominante, mas aparece com frequência suficiente em labs e ambientes orientados a distribuições para merecer menção. Para a análise de security, ele é outro lembrete de que o conceito de "container" abrange vários ecossistemas e estilos operacionais.

### Apptainer / Singularity

Apptainer (anteriormente Singularity) é comum em ambientes de research e HPC. Suas trust assumptions, user workflow e execution model diferem de maneiras importantes das stacks centradas em Docker/Kubernetes. Em particular, esses ambientes geralmente se preocupam muito em permitir que usuários executem workloads empacotados sem conceder a eles amplos poderes privilegiados de gerenciamento de containers. Se um reviewer presumir que todo ambiente de containers é basicamente "Docker em um server", entenderá essas deployments de forma completamente errada.

## Build-Time Tooling

Muitas discussões de security falam apenas sobre runtime, mas as ferramentas de build-time também são importantes porque determinam o conteúdo das images, a exposição de build secrets e quanto contexto confiável é incorporado ao artifact final.

**BuildKit** e `docker buildx` são backends modernos de build que oferecem recursos como caching, secret mounting, SSH forwarding e builds multi-platform. Esses recursos são úteis, mas, do ponto de vista de security, também criam locais onde secrets podem sofrer leak para image layers ou onde um build context excessivamente amplo pode expor arquivos que nunca deveriam ter sido incluídos. **Buildah** desempenha uma função semelhante em ecossistemas nativos de OCI, especialmente junto ao Podman, enquanto o **Kaniko** é frequentemente usado em ambientes de CI que não querem conceder um Docker daemon privilegiado ao build pipeline.

A principal lição é que a criação de images e a execução de images são fases diferentes, mas um build pipeline fraco pode criar uma postura de runtime fraca muito antes de o container ser iniciado.

## Orchestration É Outra Camada, Não O Runtime

O Kubernetes não deve ser mentalmente igualado ao próprio runtime. Kubernetes é o orchestrator. Ele agenda Pods, armazena o estado desejado e expressa políticas de security por meio da configuração dos workloads. O kubelet então conversa com uma implementação de CRI, como containerd ou CRI-O, que, por sua vez, invoca um runtime de baixo nível, como `runc`, `crun`, `runsc` ou `kata-runtime`.

Essa separação é importante porque muitas pessoas atribuem incorretamente uma proteção ao "Kubernetes", quando ela é realmente aplicada pelo node runtime, ou culpam os "defaults do containerd" por um comportamento originado de um Pod spec. Na prática, a postura final de security é uma composição: o orchestrator solicita algo, a runtime stack traduz essa solicitação e o kernel finalmente a aplica.

## Por Que A Identificação Do Runtime É Importante Durante A Assessment

Se você identificar o engine e o runtime cedo, muitas observações posteriores se tornam mais fáceis de interpretar. Um container rootless do Podman sugere que user namespaces provavelmente fazem parte da situação. Um Docker socket montado em um workload sugere que uma privilege escalation orientada por API é um caminho realista. Um node CRI-O/OpenShift deve imediatamente fazer você pensar em SELinux labels e restricted workload policy. Um ambiente gVisor ou Kata deve torná-lo mais cauteloso ao presumir que uma classic `runc` breakout PoC se comportará da mesma forma.

É por isso que uma das primeiras etapas de uma container assessment deve ser sempre responder a duas perguntas simples: **qual componente está gerenciando o container** e **qual runtime realmente iniciou o processo**. Quando essas respostas estão claras, o restante do ambiente geralmente se torna muito mais fácil de analisar.

## Runtime Vulnerabilities

Nem todo container escape é causado por uma misconfiguration do operador. Às vezes, o próprio runtime é o componente vulnerável. Isso é importante porque um workload pode estar sendo executado com uma configuração aparentemente cuidadosa e ainda assim estar exposto por meio de uma falha no runtime de baixo nível.

O exemplo clássico é a **CVE-2019-5736** no `runc`, na qual um container malicioso poderia sobrescrever o binário `runc` do host e aguardar uma chamada posterior de `docker exec` ou uma invocação semelhante do runtime para disparar código controlado pelo attacker. O exploit path é muito diferente de um simples erro de bind-mount ou capability, porque abusa da forma como o runtime reentra no process space do container durante o tratamento de exec.

Um workflow de reprodução mínimo sob a perspectiva de um red-team é:
```bash
go build main.go
./main
```
Então, a partir do host:
```bash
docker exec -it <container-name> /bin/sh
```
A principal lição não é a implementação exata do exploit histórico, mas a implicação para a avaliação: se a versão do runtime for vulnerável, a execução comum de código dentro do container pode ser suficiente para comprometer o host, mesmo quando a configuração visível do container não parece evidentemente fraca.

CVEs recentes do runtime, como `CVE-2024-21626` no `runc`, condições de corrida de mount no BuildKit e bugs de parsing no containerd, reforçam o mesmo ponto. A versão e o nível de patch do runtime fazem parte da fronteira de segurança, não são apenas detalhes de manutenção.
{{#include ../../../banners/hacktricks-training.md}}
