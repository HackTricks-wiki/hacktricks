# Runtimes, Engines, Builders E Sandboxes de Container

{{#include ../../../banners/hacktricks-training.md}}

Uma das maiores fontes de confusão em segurança de container é que vários componentes completamente diferentes frequentemente são condensados na mesma palavra. "Docker" pode referir-se a um formato de imagem, uma CLI, um daemon, um sistema de build, uma stack de runtime, ou simplesmente à ideia de containers em geral. Para trabalho de segurança, essa ambiguidade é um problema, porque camadas diferentes são responsáveis por proteções diferentes. Um escape causado por um bind mount mal configurado não é a mesma coisa que um escape causado por um bug de runtime de baixo nível, e nenhum dos dois é a mesma coisa que um erro de política de cluster no Kubernetes.

Esta página separa o ecossistema por função para que o restante da seção possa falar com precisão sobre onde uma proteção ou fraqueza realmente reside.

## OCI Como Linguagem Comum

Stacks modernos de containers no Linux frequentemente interoperam porque falam um conjunto de especificações OCI. A **OCI Image Specification** descreve como imagens e layers são representados. A **OCI Runtime Specification** descreve como o runtime deve lançar o processo, incluindo namespaces, mounts, cgroups e configurações de segurança. A **OCI Distribution Specification** padroniza como registries expõem conteúdo.

Isso é importante porque explica por que uma imagem de container construída com uma ferramenta pode frequentemente ser executada com outra, e por que vários engines podem compartilhar o mesmo runtime de baixo nível. Também explica por que o comportamento de segurança pode parecer similar entre produtos diferentes: muitos deles estão construindo a mesma configuração de runtime OCI e entregando-a ao mesmo pequeno conjunto de runtimes.

## Runtimes OCI de Baixo Nível

O runtime de baixo nível é o componente que está mais próximo da fronteira com o kernel. É a parte que realmente cria namespaces, escreve configurações de cgroup, aplica capabilities e filtros seccomp, e finalmente `execve()` o processo do container. Quando as pessoas discutem "isolamento de container" no nível mecânico, essa é a camada à qual geralmente se referem, mesmo que não digam isso explicitamente.

### `runc`

`runc` é o runtime OCI de referência e continua sendo a implementação mais conhecida. É muito usado sob Docker, containerd e muitas implantações de Kubernetes. Muito material público de pesquisa e exploração tem como alvo ambientes no estilo `runc` simplesmente porque são comuns e porque `runc` define a baseline que muitas pessoas imaginam quando pensam em um container Linux. Entender `runc` dá portanto ao leitor um modelo mental forte para o isolamento clássico de container.

### `crun`

`crun` é outro runtime OCI, escrito em C e amplamente usado em ambientes modernos do Podman. Frequentemente é elogiado pelo bom suporte a cgroup v2, fortes ergonomias rootless, e menor overhead. Do ponto de vista de segurança, o importante não é que ele seja escrito em uma linguagem diferente, mas que ele ainda desempenha o mesmo papel: é o componente que transforma a configuração OCI em uma árvore de processos em execução sob o kernel. Um fluxo rootless do Podman frequentemente acaba parecendo mais seguro não porque `crun` conserte magicamente tudo, mas porque a stack ao redor tende a forçar mais o uso de user namespaces e princípio de menor privilégio.

### `runsc` Do gVisor

`runsc` é o runtime usado pelo gVisor. Aqui a fronteira muda de forma significativa. Em vez de passar a maioria das syscalls diretamente para o kernel host do jeito usual, o gVisor insere uma camada de kernel em espaço de usuário que emula ou media grande parte da interface Linux. O resultado não é um container `runc` normal com algumas flags extras; é um design de sandbox diferente cujo propósito é reduzir a superfície de ataque do kernel host. Compatibilidade e tradeoffs de performance fazem parte desse design, então ambientes que usam `runsc` devem ser documentados de forma diferente dos ambientes normais de runtime OCI.

### `kata-runtime`

Kata Containers empurram a fronteira mais adiante ao lançar a carga de trabalho dentro de uma máquina virtual leve. Administrativamente, isso ainda pode parecer uma implantação de container, e camadas de orquestração podem tratá-la como tal, mas a fronteira de isolamento subjacente está mais próxima da virtualização do que de um container clássico que compartilha o kernel do host. Isso torna o Kata útil quando se deseja um isolamento de tenant mais forte sem abandonar fluxos de trabalho centrados em container.

## Engines E Managers de Container

Se o runtime de baixo nível é o componente que fala diretamente com o kernel, o engine ou manager é o componente com o qual usuários e operadores geralmente interagem. Ele lida com pulls de imagem, metadata, logs, redes, volumes, operações de lifecycle e exposição de API. Essa camada importa enormemente porque muitos comprometimentos do mundo real acontecem aqui: acesso a um socket de runtime ou API do daemon pode equivaler a comprometimento do host mesmo se o runtime de baixo nível estiver perfeitamente saudável.

### Docker Engine

Docker Engine é a plataforma de container mais reconhecível para desenvolvedores e uma das razões pelas quais o vocabulário de container ficou tão moldado pelo Docker. O caminho típico é a CLI `docker` para `dockerd`, que por sua vez coordena componentes de nível inferior como `containerd` e um runtime OCI. Historicamente, implantações Docker têm sido frequentemente **rootful**, e acesso ao socket do Docker tem sido portanto uma primitiva muito poderosa. É por isso que tanto material prático de elevação de privilégio foca em `docker.sock`: se um processo pode pedir ao `dockerd` para criar um container privilegiado, montar caminhos do host ou entrar em namespaces do host, pode não precisar de um exploit de kernel.

### Podman

Podman foi projetado em torno de um modelo mais sem daemon. Operacionalmente, isso ajuda a reforçar a ideia de que containers são apenas processos gerenciados pelos mecanismos padrão do Linux em vez de por um daemon privilegiado de longa duração. Podman também tem uma história **rootless** muito mais forte do que as implantações clássicas do Docker que muitas pessoas aprenderam primeiro. Isso não torna o Podman automaticamente seguro, mas muda o perfil de risco padrão de forma significativa, especialmente quando combinado com user namespaces, SELinux e `crun`.

### containerd

containerd é um componente central de gerenciamento de runtime em muitas stacks modernas. É usado sob Docker e também é um dos backends de runtime dominantes do Kubernetes. Ele expõe APIs poderosas, gerencia imagens e snapshots, e delega a criação final do processo para um runtime de baixo nível. Discussões de segurança sobre containerd devem enfatizar que acesso ao socket do containerd ou à funcionalidade de `ctr`/`nerdctl` pode ser tão perigoso quanto acesso à API do Docker, mesmo se a interface e o fluxo de trabalho parecerem menos "amigáveis ao desenvolvedor".

### CRI-O

CRI-O é mais focado do que o Docker Engine. Em vez de ser uma plataforma de uso geral para desenvolvedores, ele é construído em torno da implementação limpa da Kubernetes Container Runtime Interface. Isso o torna especialmente comum em distribuições Kubernetes e ecossistemas pesados em SELinux, como o OpenShift. Do ponto de vista de segurança, esse escopo mais estreito é útil porque reduz a confusão conceitual: CRI-O é muito parte da camada "rodar containers para Kubernetes" em vez de uma plataforma que faz tudo.

### Incus, LXD E LXC

Sistemas Incus/LXD/LXC valem ser separados de containers estilo Docker porque frequentemente são usados como **system containers**. Um system container normalmente se espera que se pareça mais com uma máquina leve com um userspace mais completo, serviços de longa duração, exposição de dispositivos mais rica e integração com o host mais extensa. Os mecanismos de isolamento ainda são primitivos do kernel, mas as expectativas operacionais são diferentes. Como resultado, más configurações aqui frequentemente parecem menos com "padrões ruins de app-container" e mais com erros em virtualização leve ou delegação de host.

### systemd-nspawn

systemd-nspawn ocupa um lugar interessante porque é nativo do systemd e muito útil para testes, debug e execução de ambientes parecidos com um OS. Não é o runtime dominante de produção cloud-native, mas aparece com frequência suficiente em labs e ambientes orientados a distro para merecer menção. Para análise de segurança, é outro lembrete de que o conceito "container" abrange múltiplos ecossistemas e estilos operacionais.

### Apptainer / Singularity

Apptainer (anteriormente Singularity) é comum em ambientes de pesquisa e HPC. Suas suposições de confiança, fluxo de trabalho do usuário e modelo de execução diferem de formas importantes das stacks centradas em Docker/Kubernetes. Em particular, esses ambientes frequentemente se preocupam profundamente em permitir que usuários executem cargas empacotadas sem lhes conceder amplos poderes de gerenciamento privilegiado de containers. Se um avaliador assumir que todo ambiente de container é basicamente "Docker em um servidor", ele vai entender mal essas implantações.

## Tooling de Build

Muitas discussões de segurança falam apenas sobre o tempo de execução, mas o tooling de build também importa porque determina o conteúdo da imagem, exposição de secrets durante o build, e quanto contexto confiável é embutido no artefato final.

**BuildKit** e `docker buildx` são backends de build modernos que suportam recursos como caching, montagem de secrets, forwarding de SSH e builds multi-plataforma. Essas são funcionalidades úteis, mas do ponto de vista de segurança também criam lugares onde secrets podem vazar para layers de imagem ou onde um contexto de build excessivamente amplo pode expor arquivos que nunca deveriam ter sido incluídos. **Buildah** desempenha um papel semelhante em ecossistemas OCI-native, especialmente ao redor do Podman, enquanto **Kaniko** é frequentemente usado em CI que não quer conceder um daemon Docker privilegiado à pipeline de build.

A lição chave é que criação de imagem e execução de imagem são fases diferentes, mas uma pipeline de build fraca pode criar uma postura de runtime fraca muito antes do container ser lançado.

## Orquestração É Outra Camada, Não O Runtime

Kubernetes não deve ser mentalmente equiparado ao runtime em si. Kubernetes é o orquestrador. Ele agenda Pods, armazena o estado desejado e expressa políticas de segurança através da configuração de workloads. O kubelet então fala com uma implementação CRI como containerd ou CRI-O, que por sua vez invoca um runtime de baixo nível como `runc`, `crun`, `runsc` ou `kata-runtime`.

Essa separação importa porque muitas pessoas atribuem erroneamente uma proteção ao "Kubernetes" quando ela é realmente aplicada pelo runtime do node, ou culpam os "defaults do containerd" por um comportamento que veio de um spec de Pod. Na prática, a postura final de segurança é uma composição: o orquestrador pede algo, a stack de runtime o traduz, e o kernel finalmente o aplica.

## Por Que Identificar o Runtime Importa Durante Avaliação

Se você identificar o engine e o runtime cedo, muitas observações posteriores ficam mais fáceis de interpretar. Um container Podman rootless sugere que user namespaces provavelmente fazem parte da história. Um socket Docker montado em uma carga de trabalho sugere que uma escalada de privilégio via API é um caminho realista. Um node CRI-O/OpenShift deve imediatamente fazê-lo pensar sobre labels SELinux e políticas de workload restritas. Um ambiente gVisor ou Kata deve deixá-lo mais cauteloso antes de assumir que um PoC clássico de breakout em `runc` se comportará da mesma maneira.

É por isso que um dos primeiros passos em uma avaliação de container deve sempre ser responder duas perguntas simples: **qual componente está gerenciando o container** e **qual runtime realmente lançou o processo**. Uma vez que essas respostas estejam claras, o restante do ambiente normalmente se torna muito mais fácil de raciocinar.

## Vulnerabilidades de Runtime

Nem todo escape de container vem de má configuração do operador. Às vezes o próprio runtime é o componente vulnerável. Isso importa porque uma carga de trabalho pode estar rodando com o que parece ser uma configuração cuidadosa e ainda assim estar exposta por uma falha de runtime de baixo nível.

O exemplo clássico é **CVE-2019-5736** em `runc`, onde um container malicioso podia sobrescrever o binário `runc` do host e então esperar por um posterior `docker exec` ou invocação de runtime similar para disparar código controlado pelo atacante. O caminho de exploração é muito diferente de um simples erro de bind-mount ou capability porque abusa de como o runtime reentra no espaço do processo do container durante o tratamento de exec.

Um fluxo mínimo de reprodução do ponto de vista de um red-team é:
```bash
go build main.go
./main
```
Então, a partir do host:
```bash
docker exec -it <container-name> /bin/sh
```
A lição principal não é a implementação histórica exata do exploit, mas a implicação para a avaliação: se a versão do runtime for vulnerável, uma execução de código comum in-container pode ser suficiente para comprometer o host mesmo quando a configuração visível do container não parece claramente fraca.

CVEs recentes de runtime, como `CVE-2024-21626` em `runc`, BuildKit mount races e bugs de parsing do containerd reforçam o mesmo ponto. A versão do runtime e o nível de patch fazem parte do perímetro de segurança, não meramente detalhes triviais de manutenção.
