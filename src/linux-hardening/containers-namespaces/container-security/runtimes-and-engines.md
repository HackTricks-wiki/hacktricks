# Runtimes, Engines, Builders E Sandboxes De Containers

Uma das maiores fontes de confusão em container security é que vários componentes completamente diferentes costumam ser agrupados sob a mesma palavra. "Docker" pode se referir a um formato de imagem, uma CLI, um daemon, um sistema de build, uma runtime stack ou simplesmente à ideia de containers em geral. Para trabalhos de security, essa ambiguidade é um problema, porque diferentes camadas são responsáveis por diferentes proteções. Um breakout causado por um bind mount incorreto não é a mesma coisa que um breakout causado por um bug no low-level runtime, e nenhum dos dois é igual a um erro de política do cluster no Kubernetes.

Esta página separa o ecossistema por função para que o restante da seção possa indicar com precisão onde uma proteção ou fraqueza realmente está localizada.

## OCI Como A Linguagem Comum

As stacks modernas de containers Linux frequentemente interoperam porque utilizam um conjunto de especificações OCI. A **OCI Image Specification** descreve como imagens e layers são representadas. A **OCI Runtime Specification** descreve como o runtime deve iniciar o processo, incluindo namespaces, mounts, cgroups e configurações de security. A **OCI Distribution Specification** padroniza como os registries expõem conteúdo.

Isso é importante porque explica por que uma container image criada com uma ferramenta geralmente pode ser executada com outra, e por que vários engines podem compartilhar o mesmo low-level runtime. Também explica por que o comportamento de security pode parecer semelhante em diferentes produtos: muitos deles estão construindo a mesma configuração de OCI runtime e entregando-a ao mesmo pequeno conjunto de runtimes.

## Low-Level OCI Runtimes

O low-level runtime é o componente mais próximo da fronteira com o kernel. É a parte que realmente cria namespaces, grava configurações de cgroup, aplica capabilities e filtros seccomp e, por fim, executa `execve()` no processo do container. Quando as pessoas discutem "container isolation" no nível mecânico, geralmente estão falando desta camada, mesmo que não o digam explicitamente.

### `runc`

`runc` é o OCI runtime de referência e continua sendo a implementação mais conhecida. Ele é amplamente usado no Docker, containerd e em muitas implementações do Kubernetes. Grande parte das pesquisas públicas e do material de exploração tem como alvo ambientes no estilo `runc`, simplesmente porque são comuns e porque `runc` define a baseline que muitas pessoas imaginam quando pensam em um container Linux. Portanto, entender o `runc` fornece ao leitor um modelo mental sólido para o isolamento clássico de containers.

### `crun`

`crun` é outro OCI runtime, escrito em C e amplamente usado em ambientes modernos do Podman. Ele costuma ser elogiado pelo bom suporte a cgroup v2, pela boa ergonomia rootless e pelo menor overhead. Do ponto de vista de security, o importante não é ele ser escrito em uma linguagem diferente, mas continuar desempenhando a mesma função: é o componente que transforma a configuração OCI em uma árvore de processos em execução sob o kernel. Um workflow rootless do Podman frequentemente parece mais seguro não porque `crun` corrija tudo magicamente, mas porque a stack geral ao seu redor tende a priorizar mais os user namespaces e o least privilege.

### `runsc` Do gVisor

`runsc` é o runtime usado pelo gVisor. Aqui, a fronteira muda de forma significativa. Em vez de passar a maioria dos syscalls diretamente ao kernel do host da maneira usual, o gVisor insere uma camada de kernel em userspace que emula ou intermedeia grandes partes da interface Linux. O resultado não é um container `runc` normal com algumas flags adicionais; é um design de sandbox diferente, cujo objetivo é reduzir a attack surface do kernel do host. Trade-offs de compatibilidade e performance fazem parte desse design, portanto ambientes que usam `runsc` devem ser documentados de forma diferente dos ambientes normais de OCI runtime.

### `kata-runtime`

O Kata Containers amplia ainda mais a fronteira ao iniciar o workload dentro de uma lightweight virtual machine. Administrativamente, isso ainda pode parecer uma implantação de container, e as camadas de orquestração ainda podem tratá-la dessa forma, mas a fronteira de isolamento subjacente está mais próxima da virtualização do que de um container clássico que compartilha o kernel do host. Isso torna o Kata útil quando se deseja um isolamento mais forte entre tenants sem abandonar workflows centrados em containers.

## Engines E Container Managers

Se o low-level runtime é o componente que conversa diretamente com o kernel, o engine ou manager é o componente com o qual usuários e operadores normalmente interagem. Ele gerencia pulls de imagens, metadata, logs, networks, volumes, operações de lifecycle e exposição de APIs. Essa camada é extremamente importante porque muitos comprometimentos no mundo real acontecem aqui: o acesso a um runtime socket ou à API de um daemon pode ser equivalente ao comprometimento do host, mesmo que o próprio low-level runtime esteja perfeitamente saudável.

### Docker Engine

O Docker Engine é a plataforma de containers mais reconhecida pelos developers e uma das razões pelas quais o vocabulário de containers se tornou tão associado ao Docker. O caminho típico é a CLI `docker` até o `dockerd`, que por sua vez coordena componentes de nível inferior, como `containerd` e um OCI runtime. Historicamente, as implementações do Docker frequentemente foram **rootful**, e o acesso ao Docker socket tornou-se, portanto, um primitive extremamente poderoso. É por isso que grande parte do material prático sobre privilege escalation se concentra no `docker.sock`: se um processo puder solicitar ao `dockerd` a criação de um container privilegiado, montar paths do host ou ingressar em host namespaces, talvez não precise de um kernel exploit.

### Podman

O Podman foi projetado em torno de um modelo mais daemonless. Operacionalmente, isso reforça a ideia de que containers são apenas processos gerenciados por mecanismos Linux padrão, e não por um daemon privilegiado de longa duração. O Podman também possui uma história **rootless** muito mais forte do que as implementações clássicas do Docker que muitas pessoas conheceram primeiro. Isso não torna o Podman automaticamente seguro, mas altera significativamente o risk profile padrão, especialmente quando combinado com user namespaces, SELinux e `crun`.

### containerd

containerd é um componente essencial de runtime management em muitas stacks modernas. Ele é usado sob o Docker e também é um dos principais backends de runtime do Kubernetes. Ele expõe APIs poderosas, gerencia imagens e snapshots e delega a criação final do processo a um low-level runtime. As discussões de security sobre containerd devem enfatizar que o acesso ao socket do containerd ou às funcionalidades de `ctr`/`nerdctl` pode ser tão perigoso quanto o acesso à API do Docker, mesmo que a interface e o workflow pareçam menos "developer friendly".

### CRI-O

O CRI-O é mais focado que o Docker Engine. Em vez de ser uma plataforma de uso geral para developers, ele foi criado para implementar de forma limpa a Kubernetes Container Runtime Interface. Isso o torna especialmente comum em distribuições Kubernetes e ecossistemas centrados em SELinux, como o OpenShift. Do ponto de vista de security, esse escopo mais restrito é útil porque reduz a desordem conceitual: o CRI-O faz parte claramente da camada de "executar containers para o Kubernetes", e não de uma plataforma para tudo.

### Incus, LXD E LXC

Os sistemas Incus/LXD/LXC devem ser separados dos application containers no estilo Docker porque são frequentemente usados como **system containers**. Normalmente, espera-se que um system container se pareça mais com uma máquina lightweight, com um userspace mais completo, serviços de longa duração, exposição mais rica de devices e integração mais ampla com o host. Os mecanismos de isolamento ainda são primitives do kernel, mas as expectativas operacionais são diferentes. Como resultado, as misconfigurations aqui frequentemente se parecem menos com "defaults ruins de app-container" e mais com erros em lightweight virtualization ou host delegation.

### systemd-nspawn

systemd-nspawn ocupa uma posição interessante porque é nativo do systemd e muito útil para testing, debugging e execução de ambientes semelhantes a sistemas operacionais. Não é o runtime dominante em produção cloud-native, mas aparece com frequência suficiente em labs e ambientes orientados a distribuições para merecer menção. Para a análise de security, ele é outro lembrete de que o conceito de "container" abrange vários ecossistemas e estilos operacionais.

### Apptainer / Singularity

Apptainer (anteriormente Singularity) é comum em ambientes de research e HPC. Seus trust assumptions, workflow de usuários e execution model diferem de maneiras importantes das stacks centradas em Docker/Kubernetes. Em particular, esses ambientes geralmente se preocupam profundamente em permitir que usuários executem workloads empacotados sem conceder a eles amplos poderes privilegiados de container management. Se um reviewer presumir que todo ambiente de containers é basicamente "Docker em um server", ele entenderá essas implementações de forma completamente errada.

## Build-Time Tooling

Muitas discussões de security falam apenas sobre runtime, mas o build-time tooling também importa porque determina o conteúdo das imagens, a exposição de build secrets e quanto contexto confiável é incorporado ao artifact final.

**BuildKit** e `docker buildx` são backends modernos de build que oferecem recursos como caching, secret mounting, SSH forwarding e builds multiplatform. Esses recursos são úteis, mas, do ponto de vista de security, também criam locais onde secrets podem vazar para image layers ou onde um build context amplo demais pode expor arquivos que nunca deveriam ter sido incluídos. **Buildah** desempenha uma função semelhante em ecossistemas nativos de OCI, especialmente junto ao Podman, enquanto **Kaniko** é frequentemente usado em ambientes de CI que não querem conceder um Docker daemon privilegiado ao build pipeline.

A principal lição é que a criação e a execução de imagens são fases diferentes, mas um build pipeline fraco pode criar uma postura de security fraca muito antes de o container ser iniciado.

## Orchestration É Outra Camada, Não O Runtime

O Kubernetes não deve ser mentalmente equiparado ao runtime. Kubernetes é o orchestrator. Ele agenda Pods, armazena o estado desejado e expressa a security policy por meio da configuração dos workloads. O kubelet então conversa com uma implementação de CRI, como containerd ou CRI-O, que por sua vez invoca um low-level runtime, como `runc`, `crun`, `runsc` ou `kata-runtime`.

Essa separação é importante porque muitas pessoas atribuem incorretamente uma proteção ao "Kubernetes" quando ela é realmente aplicada pelo node runtime, ou culpam os "defaults do containerd" por um comportamento que veio de um Pod spec. Na prática, a postura final de security é uma composição: o orchestrator solicita algo, a runtime stack traduz essa solicitação e o kernel finalmente a aplica.

## Por Que A Identificação Do Runtime Importa Durante O Assessment

Se você identificar o engine e o runtime logo no início, muitas observações posteriores se tornam mais fáceis de interpretar. Um container rootless do Podman sugere que user namespaces provavelmente fazem parte do cenário. Um Docker socket montado em um workload sugere que privilege escalation orientada por API é um caminho realista. Um node CRI-O/OpenShift deve imediatamente fazê-lo pensar em SELinux labels e restricted workload policy. Um ambiente gVisor ou Kata deve torná-lo mais cauteloso ao presumir que um breakout PoC clássico de `runc` funcionará da mesma forma.

É por isso que um dos primeiros passos em um container assessment deve ser sempre responder a duas perguntas simples: **qual componente está gerenciando o container** e **qual runtime realmente iniciou o processo**. Quando essas respostas estiverem claras, o restante do ambiente normalmente se torna muito mais fácil de analisar.

## Runtime Vulnerabilities

Nem todo container escape é causado por operator misconfiguration. Às vezes, o próprio runtime é o componente vulnerável. Isso importa porque um workload pode estar sendo executado com uma configuração aparentemente cuidadosa e ainda assim estar exposto por uma falha em um low-level runtime.

O exemplo clássico é a **CVE-2019-5736** no `runc`, na qual um container malicioso poderia sobrescrever o binário `runc` do host e então esperar que uma invocação posterior de `docker exec` ou similar acionasse código controlado pelo attacker. O exploit path é muito diferente de um simples erro de bind-mount ou capability, porque explora a forma como o runtime reentra no process space do container durante o tratamento do exec.<sup>[[1]](#references)</sup>

Um workflow de reprodução mínimo, do ponto de vista de um red team, é:
```bash
go build main.go
./main
```
Em seguida, a partir do host:
```bash
docker exec -it <container-name> /bin/sh
```
A principal lição não é a implementação exata do exploit histórico, mas a implicação para a avaliação: se a versão do runtime for vulnerável, a simples execução de código dentro do container pode ser suficiente para comprometer o host, mesmo quando a configuração visível do container não parece evidentemente fraca.

CVEs recentes de runtimes, como `CVE-2024-21626` no `runc`, condições de corrida de mount no BuildKit e bugs de parsing no containerd, reforçam o mesmo ponto. A versão e o nível de patch do runtime fazem parte da fronteira de segurança, não são apenas detalhes triviais de manutenção.

## References

- [1] [Escapando do Docker via runC – Explicando a CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
{{#include ../../../banners/hacktricks-training.md}}
