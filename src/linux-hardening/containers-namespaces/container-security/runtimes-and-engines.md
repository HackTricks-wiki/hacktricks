# Container Runtimes, Engines, Builders, And Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Uma das maiores fontes de confusão em container security é que vários componentes completamente diferentes costumam ser agrupados sob a mesma palavra. "Docker" pode se referir a um formato de imagem, uma CLI, um daemon, um sistema de build, uma stack de runtime ou simplesmente à ideia de containers em geral. Para trabalhos de security, essa ambiguidade é um problema, porque diferentes camadas são responsáveis por diferentes proteções. Um breakout causado por um bind mount incorreto não é a mesma coisa que um breakout causado por um bug no low-level runtime, e nenhum dos dois é igual a um erro de policy no cluster do Kubernetes.

Esta página separa o ecossistema por função para que o restante da seção possa explicar com precisão onde uma proteção ou weakness realmente está localizada.

## OCI As The Common Language

As stacks modernas de containers Linux geralmente interoperam porque falam um conjunto de especificações OCI. A **OCI Image Specification** descreve como as imagens e as layers são representadas. A **OCI Runtime Specification** descreve como o runtime deve iniciar o processo, incluindo namespaces, mounts, cgroups e security settings. A **OCI Distribution Specification** padroniza como os registries expõem conteúdo.

Isso é importante porque explica por que uma container image criada com uma ferramenta frequentemente pode ser executada com outra, e por que vários engines podem compartilhar o mesmo low-level runtime. Também explica por que o comportamento de security pode parecer semelhante em diferentes produtos: muitos deles estão construindo a mesma configuração de OCI runtime e entregando-a ao mesmo pequeno conjunto de runtimes.

## Low-Level OCI Runtimes

O low-level runtime é o componente mais próximo da fronteira com o kernel. É a parte que realmente cria namespaces, grava configurações de cgroup, aplica capabilities e filtros seccomp e, por fim, executa `execve()` no processo do container. Quando as pessoas discutem "container isolation" no nível mecânico, geralmente estão falando desta camada, mesmo que não o digam explicitamente.

### `runc`

`runc` é o OCI runtime de referência e continua sendo a implementação mais conhecida. Ele é amplamente usado pelo Docker, containerd e em muitas implementações do Kubernetes. Grande parte das pesquisas públicas e do material de exploração tem como alvo ambientes no estilo `runc`, simplesmente porque são comuns e porque `runc` define o baseline que muitas pessoas imaginam quando pensam em um container Linux. Portanto, entender o `runc` fornece ao leitor um modelo mental sólido para o isolamento clássico de containers.

### `crun`

`crun` é outro OCI runtime, escrito em C e amplamente usado em ambientes modernos do Podman. Ele é frequentemente elogiado pelo bom suporte a cgroup v2, pela boa ergonomia rootless e pelo menor overhead. Do ponto de vista de security, o importante não é que ele seja escrito em uma linguagem diferente, mas que ainda desempenha a mesma função: é o componente que transforma a configuração OCI em uma process tree em execução sob o kernel. Um workflow rootless do Podman frequentemente acaba parecendo mais seguro não porque `crun` corrija magicamente tudo, mas porque a stack geral ao redor dele tende a priorizar mais user namespaces e least privilege.

### `runsc` From gVisor

`runsc` é o runtime usado pelo gVisor. Aqui, a fronteira muda de maneira significativa. Em vez de passar a maioria dos syscalls diretamente ao kernel do host da maneira usual, o gVisor insere uma camada de kernel em userspace que emula ou medeia grandes partes da interface Linux. O resultado não é um container `runc` normal com algumas flags adicionais; é um design de sandbox diferente, cujo objetivo é reduzir a attack surface do kernel do host. Trade-offs de compatibilidade e performance fazem parte desse design, portanto ambientes que usam `runsc` devem ser documentados de forma diferente dos ambientes OCI runtime normais.

### `kata-runtime`

O Kata Containers amplia ainda mais a fronteira ao executar o workload dentro de uma lightweight virtual machine. Administrativamente, isso ainda pode parecer uma implantação de container, e as orchestration layers ainda podem tratá-la dessa forma, mas a isolation boundary subjacente está mais próxima da virtualization do que de um container clássico que compartilha o kernel do host. Isso torna o Kata útil quando se deseja uma tenant isolation mais forte sem abandonar workflows centrados em containers.

## Engines And Container Managers

Se o low-level runtime é o componente que se comunica diretamente com o kernel, o engine ou manager é o componente com o qual usuários e operadores normalmente interagem. Ele gerencia image pulls, metadata, logs, networks, volumes, operações de lifecycle e exposição de APIs. Esta camada é extremamente importante porque muitos compromises do mundo real acontecem aqui: o acesso a um runtime socket ou à API de um daemon pode equivaler ao compromise do host, mesmo que o low-level runtime esteja perfeitamente saudável.

### Docker Engine

Docker Engine é a plataforma de containers mais reconhecida entre desenvolvedores e uma das razões pelas quais o vocabulário de containers se tornou tão orientado ao Docker. O caminho típico é a CLI `docker` até o `dockerd`, que, por sua vez, coordena componentes de nível inferior, como `containerd` e um OCI runtime. Historicamente, as implementações do Docker frequentemente foram **rootful**, e o acesso ao Docker socket consequentemente se tornou um primitive muito poderoso. É por isso que grande parte do material prático sobre privilege escalation se concentra no `docker.sock`: se um processo pode pedir ao `dockerd` para criar um container privilegiado, montar paths do host ou ingressar em host namespaces, talvez nem precise de um kernel exploit.

### Podman

O Podman foi projetado com base em um modelo mais daemonless. Operacionalmente, isso ajuda a reforçar a ideia de que containers são apenas processos gerenciados por mecanismos Linux padrão, e não por um daemon privilegiado de longa duração. O Podman também possui uma história **rootless** muito mais forte do que as implementações clássicas do Docker que muitas pessoas aprenderam primeiro. Isso não torna o Podman automaticamente seguro, mas muda significativamente o risk profile padrão, especialmente quando combinado com user namespaces, SELinux e `crun`.

### containerd

containerd é um componente central de gerenciamento de runtime em muitas stacks modernas. Ele é usado pelo Docker e também é um dos principais backends de runtime do Kubernetes. Ele expõe APIs poderosas, gerencia images e snapshots e delega a criação final do processo a um low-level runtime. As discussões de security sobre containerd devem enfatizar que o acesso ao socket do containerd ou às funcionalidades de `ctr`/`nerdctl` pode ser tão perigoso quanto o acesso à API do Docker, mesmo que a interface e o workflow pareçam menos "developer friendly".

### CRI-O

CRI-O é mais focado do que o Docker Engine. Em vez de ser uma plataforma de developer de uso geral, ele foi criado para implementar de forma limpa o Kubernetes Container Runtime Interface. Isso o torna especialmente comum em distribuições Kubernetes e em ecosystems com uso intenso de SELinux, como o OpenShift. Do ponto de vista de security, esse escopo mais restrito é útil porque reduz a confusão conceitual: o CRI-O faz claramente parte da camada "executar containers para o Kubernetes", e não de uma plataforma completa.

### Incus, LXD, And LXC

Sistemas Incus/LXD/LXC merecem ser separados dos application containers no estilo Docker porque são frequentemente usados como **system containers**. Normalmente, espera-se que um system container se pareça mais com uma lightweight machine, com um userspace mais completo, serviços de longa duração, maior exposição de devices e integração mais extensa com o host. Os mecanismos de isolation ainda são primitives do kernel, mas as expectativas operacionais são diferentes. Como resultado, as misconfigurations aqui frequentemente se parecem menos com "bad app-container defaults" e mais com erros de lightweight virtualization ou de host delegation.

### systemd-nspawn

systemd-nspawn ocupa uma posição interessante porque é nativo do systemd e muito útil para testing, debugging e execução de ambientes semelhantes a sistemas operacionais. Ele não é o runtime de produção dominante em ambientes cloud-native, mas aparece com frequência suficiente em labs e ambientes orientados a distribuições para merecer uma menção. Para a análise de security, ele é outro lembrete de que o conceito de "container" abrange vários ecosystems e estilos operacionais.

### Apptainer / Singularity

Apptainer (anteriormente Singularity) é comum em ambientes de pesquisa e HPC. Suas trust assumptions, user workflow e execution model diferem de maneiras importantes das stacks centradas em Docker/Kubernetes. Em particular, esses ambientes geralmente se preocupam profundamente em permitir que usuários executem workloads empacotados sem conceder a eles amplos poderes privilegiados de gerenciamento de containers. Se um reviewer presumir que todo ambiente de containers é basicamente "Docker em um servidor", ele entenderá essas implementações de forma bastante equivocada.

## Build-Time Tooling

Muitas discussões de security falam apenas sobre runtime, mas as ferramentas de build-time também são importantes porque determinam o conteúdo das images, a exposição de build secrets e quanto trusted context é incorporado ao artifact final.

**BuildKit** e `docker buildx` são backends modernos de build que oferecem recursos como caching, secret mounting, SSH forwarding e builds multi-platform. Esses recursos são úteis, mas, do ponto de vista de security, também criam locais onde secrets podem sofrer leak nas image layers ou onde um build context amplo demais pode expor arquivos que nunca deveriam ter sido incluídos. **Buildah** desempenha uma função semelhante em ecosystems nativos de OCI, especialmente junto ao Podman, enquanto o **Kaniko** é frequentemente usado em ambientes de CI que não querem conceder um Docker daemon privilegiado ao build pipeline.

A principal lição é que a criação de images e a execução de images são fases diferentes, mas um build pipeline fraco pode criar uma postura de security fraca muito antes de o container ser iniciado.

## Orchestration Is Another Layer, Not The Runtime

O Kubernetes não deve ser mentalmente equiparado ao runtime. Kubernetes é o orchestrator. Ele agenda Pods, armazena o desired state e expressa security policy por meio da configuração dos workloads. O kubelet então se comunica com uma implementação de CRI, como containerd ou CRI-O, que, por sua vez, invoca um low-level runtime, como `runc`, `crun`, `runsc` ou `kata-runtime`.

Essa separação é importante porque muitas pessoas atribuem incorretamente uma proteção ao "Kubernetes", quando ela é realmente aplicada pelo node runtime, ou culpam os "containerd defaults" por um comportamento que veio de um Pod spec. Na prática, a postura final de security é uma composição: o orchestrator solicita algo, a runtime stack traduz isso e o kernel finalmente aplica a regra.

## Why Runtime Identification Matters During Assessment

Se você identificar o engine e o runtime no início, muitas observações posteriores se tornam mais fáceis de interpretar. Um container rootless do Podman sugere que user namespaces provavelmente fazem parte da situação. Um Docker socket montado em um workload sugere que uma privilege escalation orientada por API é um caminho realista. Um node CRI-O/OpenShift deve imediatamente fazer você pensar em SELinux labels e restricted workload policy. Um ambiente gVisor ou Kata deve torná-lo mais cauteloso ao presumir que um breakout PoC clássico de `runc` se comportará da mesma forma.

É por isso que um dos primeiros passos em um container assessment deve ser sempre responder a duas perguntas simples: **qual componente está gerenciando o container** e **qual runtime realmente iniciou o processo**. Quando essas respostas estiverem claras, o restante do ambiente normalmente se torna muito mais fácil de analisar.

## Runtime Vulnerabilities

Nem todo container escape é causado por uma misconfiguration do operador. Às vezes, o próprio runtime é o componente vulnerável. Isso é importante porque um workload pode estar sendo executado com uma configuração aparentemente cuidadosa e ainda assim estar exposto por meio de uma falha em um low-level runtime.

O exemplo clássico é a **CVE-2019-5736** no `runc`, na qual um container malicioso poderia sobrescrever o binário `runc` do host e então aguardar uma invocação posterior de `docker exec` ou similar para que o runtime executasse código controlado pelo atacante. O exploit path é muito diferente de um simples erro de bind-mount ou capability, porque abusa da forma como o runtime reentra no process space do container durante o tratamento do exec.<sup>[[1]](#references)</sup>

Um workflow de reprodução mínima do ponto de vista de um red-team é:
```bash
go build main.go
./main
```
Então, a partir do host:
```bash
docker exec -it <container-name> /bin/sh
```
A principal lição não é a implementação exata do exploit histórico, mas a implicação para a avaliação: se a versão do runtime estiver vulnerável, a execução comum de código dentro do container pode ser suficiente para comprometer o host, mesmo quando a configuração visível do container não parece flagrantemente fraca.

CVE-IDs recentes de runtimes, como `CVE-2024-21626` no `runc`, condições de corrida de mounts no BuildKit e bugs de parsing no containerd, reforçam o mesmo ponto. A versão e o nível de patch do runtime fazem parte da security boundary, não são apenas detalhes de manutenção.

## Referências

- [1] [Breaking out of Docker via runC – Explaining CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)

{{#include ../../../banners/hacktricks-training.md}}
