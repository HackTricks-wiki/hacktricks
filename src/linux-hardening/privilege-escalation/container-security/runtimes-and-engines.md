# Runtimes de Container, Engines, Builders e Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Uma das maiores fontes de confusão em segurança de containers é que vários componentes completamente diferentes frequentemente são agrupados na mesma palavra. "Docker" pode referir-se a um image format, uma CLI, um daemon, um sistema de build, uma pilha de runtime, ou simplesmente à ideia de containers em geral. Para trabalho de segurança, essa ambiguidade é um problema, porque camadas diferentes são responsáveis por proteções diferentes. Um breakout causado por um bad bind mount não é a mesma coisa que um breakout causado por um bug de runtime de baixo nível, e nenhum dos dois é a mesma coisa que um erro de política de cluster no Kubernetes.

Esta página separa o ecossistema por função para que o restante da seção possa falar com precisão sobre onde uma proteção ou fraqueza realmente vive.

## OCI Como a Linguagem Comum

Stacks modernas de containers no Linux frequentemente interoperam porque falam um conjunto de especificações OCI. A **OCI Image Specification** descreve como imagens e camadas são representadas. A **OCI Runtime Specification** descreve como o runtime deve lançar o processo, incluindo namespaces, mounts, cgroups e configurações de segurança. A **OCI Distribution Specification** padroniza como registries expõem conteúdo.

Isso importa porque explica por que uma imagem de container construída com uma ferramenta pode frequentemente ser executada com outra, e por que vários engines podem compartilhar o mesmo runtime de baixo nível. Também explica por que o comportamento de segurança pode parecer similar entre produtos diferentes: muitos deles estão construindo a mesma configuração de runtime OCI e entregando-a ao mesmo pequeno conjunto de runtimes.

## Runtimes OCI de Baixo Nível

O runtime de baixo nível é o componente que está mais próximo da fronteira do kernel. É a parte que realmente cria namespaces, escreve configurações de cgroup, aplica capabilities e filtros seccomp, e finalmente `execve()` o processo do container. Quando as pessoas discutem "isolamento de container" no nível mecânico, é essa a camada sobre a qual geralmente estão falando, mesmo que não digam explicitamente.

### `runc`

`runc` é o runtime de referência OCI e continua sendo a implementação mais conhecida. É amplamente usado sob Docker, containerd e muitas implantações de Kubernetes. Muito material público de pesquisa e exploração mira ambientes do tipo `runc` simplesmente porque eles são comuns e porque `runc` define a linha de base que muitas pessoas pensam quando imaginam um container Linux. Entender `runc` dá, portanto, ao leitor um modelo mental forte para o isolamento clássico de containers.

### `crun`

`crun` é outro runtime OCI, escrito em C e muito usado em ambientes modernos de Podman. Frequentemente é elogiado pelo bom suporte a cgroup v2, ergonomia rootless e menor overhead. Do ponto de vista de segurança, o importante não é que ele seja escrito em uma linguagem diferente, mas que ele ainda desempenha o mesmo papel: é o componente que transforma a configuração OCI em uma árvore de processos em execução sob o kernel. Um fluxo rootless com Podman frequentemente acaba parecendo mais seguro não porque `crun` conserte tudo magicamente, mas porque a pilha ao redor tende a adotar mais user namespaces e o princípio de least privilege.

### `runsc` do gVisor

`runsc` é o runtime usado pelo gVisor. Aqui a fronteira muda significativamente. Em vez de passar a maioria dos syscalls diretamente para o kernel host da maneira usual, o gVisor insere uma camada de kernel em espaço de usuário que emula ou medita grande parte da interface Linux. O resultado não é um container `runc` normal com alguns flags extras; é um design de sandbox diferente cujo propósito é reduzir a superfície de ataque do kernel host. Compromissos de compatibilidade e performance fazem parte desse design, então ambientes que usam `runsc` devem ser documentados de forma diferente de ambientes normais de runtime OCI.

### `kata-runtime`

Kata Containers empurra a fronteira ainda mais ao lançar a carga de trabalho dentro de uma máquina virtual leve. Administrativamente, isso ainda pode parecer uma implantação de container, e camadas de orquestração podem tratá-la assim, mas a fronteira de isolamento subjacente está mais próxima da virtualização do que de um container clássico que compartilha o kernel host. Isso torna o Kata útil quando se deseja isolamento mais forte entre tenants sem abandonar fluxos de trabalho centrados em containers.

## Engines E Gerenciadores de Container

Se o runtime de baixo nível é o componente que fala diretamente com o kernel, o engine ou manager é o componente com o qual usuários e operadores normalmente interagem. Ele lida com pulls de imagem, metadata, logs, redes, volumes, operações de lifecycle e exposição de API. Essa camada importa enormemente porque muitos compromissos no mundo real acontecem aqui: acesso a um runtime socket ou API do daemon pode ser equivalente a um comprometimento do host mesmo que o runtime de baixo nível em si esteja perfeitamente saudável.

### Docker Engine

Docker Engine é a plataforma de container mais reconhecível para desenvolvedores e uma das razões pelas quais o vocabulário de containers se tornou tão "Docker-shaped". O caminho típico é o `docker` CLI para `dockerd`, que por sua vez coordena componentes de nível inferior como `containerd` e um runtime OCI. Historicamente, implantações Docker muitas vezes foram **executadas com privilégios de root**, e o acesso ao socket Docker tem, portanto, sido uma primitiva muito poderosa. É por isso que tanto material prático de escalation de privilégios foca em `docker.sock`: se um processo pode pedir ao `dockerd` para criar um container privilegiado, montar caminhos do host ou entrar em namespaces do host, pode não precisar de um exploit do kernel.

### Podman

Podman foi projetado em torno de um modelo mais daemonless. Operacionalmente, isso ajuda a reforçar a ideia de que containers são apenas processos gerenciados através de mecanismos padrão do Linux em vez de por um daemon privilegiado de longa duração. Podman também tem uma história **rootless** muito mais forte do que as implantações clássicas de Docker que muitas pessoas aprenderam primeiro. Isso não torna o Podman automaticamente seguro, mas altera significativamente o perfil de risco por padrão, especialmente quando combinado com user namespaces, SELinux e `crun`.

### containerd

containerd é um componente central de gerenciamento de runtime em muitas stacks modernas. Ele é usado sob Docker e também é um dos backends dominantes de runtime no Kubernetes. Ele expõe APIs poderosas, gerencia imagens e snapshots, e delega a criação final do processo a um runtime de baixo nível. Discussões de segurança em torno do containerd devem enfatizar que o acesso ao socket do containerd ou à funcionalidade `ctr`/`nerdctl` pode ser tão perigoso quanto o acesso à API do Docker, mesmo que a interface e o fluxo pareçam menos "amigáveis ao desenvolvedor".

### CRI-O

CRI-O é mais focado do que o Docker Engine. Em vez de ser uma plataforma de propósito geral para desenvolvedores, ele é construído em torno da implementação limpa da Kubernetes Container Runtime Interface. Isso o torna especialmente comum em distribuições Kubernetes e em ecossistemas pesados em SELinux como o OpenShift. Do ponto de vista de segurança, esse escopo mais estreito é útil porque reduz a desordem conceitual: CRI-O faz parte da camada "executar containers para Kubernetes" em vez de ser uma plataforma para tudo.

### Incus, LXD e LXC

Sistemas Incus/LXD/LXC valem ser separados dos containers ao estilo Docker porque frequentemente são usados como **system containers**. Um system container geralmente é esperado para se parecer mais com uma máquina leve com um userspace mais completo, serviços de longa duração, exposição mais rica a dispositivos e integração de host mais extensa. Os mecanismos de isolamento ainda são primitivas do kernel, mas as expectativas operacionais são diferentes. Como resultado, má configurações aqui frequentemente parecem menos com "defaults ruins de app-container" e mais com erros em virtualização leve ou delegação de host.

### systemd-nspawn

systemd-nspawn ocupa um lugar interessante porque é nativo do systemd e muito útil para testes, depuração e execução de ambientes parecidos com OS. Não é o runtime dominante em produção cloud-native, mas aparece com frequência suficiente em labs e ambientes orientados a distros para merecer menção. Para análise de segurança, é outro lembrete de que o conceito "container" abrange múltiplos ecossistemas e estilos operacionais.

### Apptainer / Singularity

Apptainer (anteriormente Singularity) é comum em ambientes de pesquisa e HPC. Suas suposições de confiança, fluxo de trabalho do usuário e modelo de execução diferem de maneiras importantes das stacks centradas em Docker/Kubernetes. Em particular, esses ambientes frequentemente valorizam permitir que usuários executem cargas empacotadas sem lhes dar amplos poderes de gerenciamento privilegiado de containers. Se um revisor assume que todo ambiente de container é basicamente "Docker em um servidor", ele vai compreender mal essas implantações.

## Ferramentas de Build

Muitas discussões de segurança falam apenas sobre o tempo de execução, mas ferramentas de build também importam porque determinam o conteúdo da imagem, exposição de build secrets e quanto contexto confiável é embutido no artefato final.

**BuildKit** e `docker buildx` são backends de build modernos que suportam recursos como caching, montagem de secrets, SSH forwarding e builds multi-plataforma. Esses são recursos úteis, mas do ponto de vista de segurança também criam pontos onde secrets podem vazar para camadas de imagem ou onde um contexto de build excessivamente amplo pode expor arquivos que nunca deveriam ter sido incluídos. **Buildah** desempenha um papel similar em ecossistemas OCI-native, especialmente ao redor do Podman, enquanto **Kaniko** é frequentemente usado em ambientes de CI que não querem conceder um daemon Docker privilegiado ao pipeline de build.

A lição chave é que criação de imagem e execução de imagem são fases diferentes, mas um pipeline de build fraco pode criar uma postura de execução fraca muito antes do container ser lançado.

## Orquestração É Outra Camada, Não O Runtime

Kubernetes não deve ser mentalmente equiparado ao runtime em si. Kubernetes é o orquestrador. Ele agenda Pods, armazena desired state e expressa políticas de segurança através da configuração de workload. O kubelet então fala com uma implementação CRI como containerd ou CRI-O, que por sua vez invoca um runtime de baixo nível como `runc`, `crun`, `runsc` ou `kata-runtime`.

Essa separação importa porque muitas pessoas atribuem erroneamente uma proteção ao "Kubernetes" quando ela é realmente aplicada pelo runtime do node, ou colocam a culpa em "containerd defaults" por um comportamento que veio de um Pod spec. Na prática, a postura final de segurança é uma composição: o orquestrador pede algo, a pilha de runtime traduz, e o kernel finalmente impõe.

## Por Que Identificar o Runtime Importa Durante a Avaliação

Se você identificar o engine e o runtime cedo, muitas observações posteriores ficam mais fáceis de interpretar. Um container Podman rootless sugere que user namespaces provavelmente fazem parte da história. Um socket Docker montado dentro de uma workload sugere que escalada de privilégios via API é um caminho realista. Um node CRI-O/OpenShift deve imediatamente fazer você pensar em SELinux labels e política de workload restrita. Um ambiente gVisor ou Kata deve deixá-lo mais cauteloso em assumir que um PoC clássico de breakout `runc` se comportará da mesma forma.

É por isso que um dos primeiros passos em uma avaliação de containers deve sempre ser responder duas perguntas simples: **qual componente está gerenciando o container** e **qual runtime realmente lançou o processo**. Uma vez que essas respostas estejam claras, o restante do ambiente geralmente se torna muito mais fácil de raciocinar.

## Vulnerabilidades de Runtime

Nem todo escape de container vem de má configuração do operador. Às vezes o próprio runtime é o componente vulnerável. Isso importa porque uma workload pode estar rodando com o que parece ser uma configuração cuidadosa e ainda assim estar exposta através de uma falha de runtime de baixo nível.

O exemplo clássico é a **CVE-2019-5736** em `runc`, onde um container malicioso poderia sobrescrever o binário `runc` do host e então esperar por um posterior `docker exec` ou invocação de runtime semelhante para disparar código controlado pelo atacante. O caminho de exploit é muito diferente de um simples bind-mount ou erro de capability porque abusa de como o runtime reentra no espaço de processo do container durante o tratamento de exec.

Um fluxo mínimo de reprodução do ponto de vista de um red-team é:
```bash
go build main.go
./main
```
Então, a partir do host:
```bash
docker exec -it <container-name> /bin/sh
```
A lição chave não é a implementação histórica exata do exploit, mas a implicação para a avaliação: se a versão do runtime for vulnerável, a execução comum de código dentro do container pode ser suficiente para comprometer o host mesmo quando a configuração visível do container não parece claramente fraca.

CVEs recentes do runtime, como `CVE-2024-21626` em `runc`, BuildKit mount races, e containerd parsing bugs reforçam o mesmo ponto. A versão do runtime e o nível de patch fazem parte da fronteira de segurança, não meramente trivialidades de manutenção.
{{#include ../../../banners/hacktricks-training.md}}
