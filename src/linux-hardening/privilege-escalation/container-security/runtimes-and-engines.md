# Container Runtimes, Engines, Builders, And Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Uma das maiores fontes de confusão em segurança de contêineres é que vários componentes completamente diferentes são frequentemente condensados na mesma palavra. "Docker" pode referir-se a um formato de imagem, uma CLI, um daemon, um sistema de build, uma pilha de runtime, ou simplesmente à ideia de contêineres em geral. Para trabalho de segurança, essa ambiguidade é um problema, porque camadas diferentes são responsáveis por proteções diferentes. Uma fuga causada por um bind mount mal configurado não é a mesma coisa que uma fuga causada por um bug de baixo nível no runtime, e nenhuma delas é a mesma coisa que um erro de política de cluster no Kubernetes.

Esta página separa o ecossistema por papel para que o restante da seção possa falar com precisão sobre onde uma proteção ou fraqueza realmente existe.

## OCI As The Common Language

Pilhas modernas de contêineres no Linux frequentemente interoperam porque falam um conjunto de especificações OCI. A **OCI Image Specification** descreve como imagens e camadas são representadas. A **OCI Runtime Specification** descreve como o runtime deve lançar o processo, incluindo namespaces, mounts, cgroups e configurações de segurança. A **OCI Distribution Specification** padroniza como os registries expõem conteúdo.

Isso importa porque explica por que uma imagem de contêiner construída com uma ferramenta pode frequentemente ser executada com outra, e por que vários engines podem compartilhar o mesmo runtime de baixo nível. Também explica por que o comportamento de segurança pode parecer semelhante entre produtos diferentes: muitos deles estão construindo a mesma configuração de runtime OCI e entregando-a ao mesmo pequeno conjunto de runtimes.

## Low-Level OCI Runtimes

O runtime de baixo nível é o componente que está mais próximo da fronteira do kernel. É a parte que realmente cria namespaces, grava configurações de cgroup, aplica capabilities e filtros seccomp, e finalmente `execve()` o processo do contêiner. Quando as pessoas discutem "isolamento de contêiner" no nível mecânico, esta é a camada sobre a qual geralmente estão falando, mesmo que não o digam explicitamente.

### `runc`

`runc` é o runtime OCI de referência e continua sendo a implementação mais conhecida. É amplamente usado sob Docker, containerd, e muitas implantações Kubernetes. Muito material público de pesquisa e exploração mira ambientes no estilo `runc` simplesmente porque são comuns e porque `runc` define a linha de base que muitas pessoas imaginam quando pensam em um contêiner Linux. Entender `runc` dá ao leitor, portanto, um forte modelo mental para o isolamento clássico de contêineres.

### `crun`

`crun` é outro runtime OCI, escrito em C e amplamente usado em ambientes modernos do Podman. Frequentemente é elogiado pelo bom suporte a cgroup v2, ergonomia rootless e menor overhead. Do ponto de vista de segurança, o importante não é que ele seja escrito em uma linguagem diferente, mas que ele ainda cumpre o mesmo papel: é o componente que transforma a configuração OCI em uma árvore de processos em execução sob o kernel. Um fluxo de trabalho rootless com Podman frequentemente acaba parecendo mais seguro não porque `crun` corrija tudo magicamente, mas porque a pilha ao redor tende a usar mais namespaces de usuário e princípio do menor privilégio.

### `runsc` From gVisor

`runsc` é o runtime usado pelo gVisor. Aqui a fronteira muda de maneira significativa. Em vez de passar a maioria das syscalls diretamente para o kernel hospedeiro da forma usual, o gVisor insere uma camada de kernel em espaço de usuário que emula ou media grande parte da interface Linux. O resultado não é um contêiner `runc` normal com algumas flags extras; é um design de sandbox diferente cujo propósito é reduzir a superfície de ataque do kernel do host. Compromissos de compatibilidade e desempenho fazem parte desse design, então ambientes usando `runsc` devem ser documentados de forma diferente de ambientes normais de runtime OCI.

### `kata-runtime`

Kata Containers empurra a fronteira ainda mais ao lançar a carga de trabalho dentro de uma máquina virtual leve. Administrativamente, isso ainda pode parecer uma implantação de contêiner, e camadas de orquestração podem ainda tratá-lo como tal, mas a fronteira de isolamento subjacente está mais próxima da virtualização do que de um contêiner clássico que compartilha o kernel do host. Isso torna o Kata útil quando se deseja um isolamento mais forte de locatários sem abandonar fluxos de trabalho centrados em contêineres.

## Engines And Container Managers

Se o runtime de baixo nível é o componente que fala diretamente com o kernel, o engine ou manager é o componente com o qual usuários e operadores normalmente interagem. Ele lida com pulls de imagem, metadados, logs, redes, volumes, operações de ciclo de vida e exposição de API. Essa camada importa enormemente porque muitos compromissos do mundo real acontecem aqui: acesso a um socket de runtime ou API de daemon pode ser equivalente a um comprometimento do host mesmo se o runtime de baixo nível estiver perfeitamente saudável.

### Docker Engine

Docker Engine é a plataforma de contêineres mais reconhecível para desenvolvedores e uma das razões de a vocabulário de contêineres ter se moldado tanto ao Docker. O caminho típico é CLI `docker` para `dockerd`, que por sua vez coordena componentes de nível inferior como `containerd` e um runtime OCI. Historicamente, implantações Docker costumavam ser **executadas como root** (rootful), e o acesso ao socket do Docker tem sido, portanto, uma primitiva muito poderosa. É por isso que tanto material prático de escalada de privilégios foca em `docker.sock`: se um processo pode pedir ao `dockerd` para criar um contêiner privilegiado, montar caminhos do host ou juntar namespaces do host, pode não precisar de um exploit de kernel.

### Podman

Podman foi projetado em torno de um modelo mais sem daemon. Operacionalmente, isso ajuda a reforçar a ideia de que contêineres são apenas processos gerenciados por mecanismos padrão do Linux em vez de por um daemon privilegiado de longa duração. Podman também tem uma história **rootless** muito mais forte do que as implantações clássicas do Docker que muitas pessoas conheceram primeiro. Isso não torna o Podman automaticamente seguro, mas muda o perfil de risco padrão de forma significativa, especialmente quando combinado com namespaces de usuário, SELinux e `crun`.

### containerd

containerd é um componente central de gerenciamento de runtime em muitas pilhas modernas. É usado sob Docker e também é um dos backends de runtime dominantes no Kubernetes. Ele expõe APIs poderosas, gerencia imagens e snapshots, e delega a criação final de processos a um runtime de baixo nível. Discussões de segurança em torno do containerd devem enfatizar que o acesso ao socket do containerd ou às funcionalidades `ctr`/`nerdctl` pode ser tão perigoso quanto o acesso à API do Docker, mesmo se a interface e o fluxo de trabalho parecerem menos "amistosos ao desenvolvedor".

### CRI-O

CRI-O é mais focado do que o Docker Engine. Em vez de ser uma plataforma de propósito geral para desenvolvedores, ele é construído em torno da implementação limpa do Kubernetes Container Runtime Interface. Isso o torna especialmente comum em distribuições Kubernetes e ecossistemas pesados em SELinux como o OpenShift. Do ponto de vista de segurança, esse escopo mais estreito é útil porque reduz a confusão conceitual: CRI-O faz parte da camada "rodar contêineres para Kubernetes" em vez de ser uma plataforma para tudo.

### Incus, LXD, And LXC

Sistemas Incus/LXD/LXC valem a separação dos contêineres ao estilo Docker porque frequentemente são usados como **system containers**. Um system container geralmente é esperado para se comportar mais como uma máquina leve com um userspace mais completo, serviços de longa execução, exposição de dispositivos mais rica e integração com o host mais extensiva. Os mecanismos de isolamento ainda são primitivos do kernel, mas as expectativas operacionais são diferentes. Como resultado, configurações erradas aqui frequentemente se parecem menos com "padrões ruins de app-container" e mais com erros em virtualização leve ou delegação de host.

### systemd-nspawn

systemd-nspawn ocupa um lugar interessante porque é nativo do systemd e muito útil para testes, debugging e execução de ambientes tipo SO. Não é o runtime dominante em produção cloud-native, mas aparece com frequência suficiente em laboratórios e ambientes orientados a distribuições para merecer menção. Para análise de segurança, é outro lembrete de que o conceito "contêiner" abrange múltiplos ecossistemas e estilos operacionais.

### Apptainer / Singularity

Apptainer (anteriormente Singularity) é comum em ambientes de pesquisa e HPC. Suas suposições de confiança, fluxo de trabalho do usuário e modelo de execução diferem de maneiras importantes das pilhas centradas em Docker/Kubernetes. Em particular, esses ambientes frequentemente se preocupam profundamente em permitir que usuários executem cargas empacotadas sem entregar a eles amplos poderes de gerenciamento de contêineres privilegiados. Se um revisor assumir que todo ambiente de contêiner é basicamente "Docker em um servidor", ele vai compreender mal essas implantações.

## Build-Time Tooling

Muita discussão de segurança fala apenas sobre tempo de execução, mas ferramentas de build também importam porque determinam o conteúdo da imagem, exposição de build secrets, e quanto contexto confiável é embutido no artefato final.

**BuildKit** e `docker buildx` são backends de build modernos que suportam recursos como caching, montagem de secrets, encaminhamento de SSH e builds multi-platforma. Esses são recursos úteis, mas do ponto de vista de segurança também criam lugares onde secrets podem vazar para camadas de imagem ou onde um contexto de build excessivamente amplo pode expor arquivos que nunca deveriam ter sido incluídos. **Buildah** desempenha papel semelhante em ecossistemas OCI-native, especialmente ao redor do Podman, enquanto **Kaniko** é frequentemente usado em ambientes de CI que não querem conceder um daemon Docker privilegiado ao pipeline de build.

A lição chave é que criação de imagem e execução de imagem são fases diferentes, mas uma pipeline de build fraca pode criar uma postura de runtime fraca muito antes do contêiner ser lançado.

## Orchestration Is Another Layer, Not The Runtime

Kubernetes não deve ser mentalmente equiparado ao próprio runtime. Kubernetes é o orquestrador. Ele agenda Pods, armazena o estado desejado e expressa política de segurança através da configuração de workload. O kubelet então fala com uma implementação CRI como containerd ou CRI-O, que por sua vez invoca um runtime de baixo nível como `runc`, `crun`, `runsc` ou `kata-runtime`.

Essa separação importa porque muitas pessoas erroneamente atribuem uma proteção ao "Kubernetes" quando ela é realmente aplicada pelo runtime do node, ou culpam "defaults do containerd" por um comportamento que veio de um Pod spec. Na prática, a postura final de segurança é uma composição: o orquestrador pede algo, a pilha de runtime traduz, e o kernel finalmente o aplica.

## Why Runtime Identification Matters During Assessment

Se você identificar o engine e o runtime cedo, muitas observações posteriores se tornam mais fáceis de interpretar. Um contêiner Podman rootless sugere que namespaces de usuário provavelmente fazem parte da história. Um socket Docker montado em uma workload sugere que escalada de privilégios via API é um caminho realista. Um node CRI-O/OpenShift deve imediatamente fazer você pensar sobre labels SELinux e política de workload restrita. Um ambiente gVisor ou Kata deve fazer você ser mais cauteloso ao assumir que um PoC clássico de breakout do `runc` vai se comportar da mesma maneira.

É por isso que um dos primeiros passos na avaliação de contêineres deve sempre ser responder duas perguntas simples: **qual componente está gerenciando o contêiner** e **qual runtime realmente lançou o processo**. Uma vez que essas respostas estejam claras, o resto do ambiente geralmente se torna muito mais fácil de raciocinar.

## Runtime Vulnerabilities

Nem toda fuga de contêiner vem de má configuração do operador. Às vezes o próprio runtime é o componente vulnerável. Isso importa porque uma workload pode estar rodando com o que parece ser uma configuração cuidadosa e ainda assim estar exposta através de uma falha de baixo nível no runtime.

O exemplo clássico é **CVE-2019-5736** em `runc`, onde um contêiner malicioso podia sobrescrever o binário `runc` do host e então esperar por um `docker exec` posterior ou invocação similar do runtime para disparar código controlado pelo atacante. O caminho do exploit é muito diferente de um simples erro de bind-mount ou capability porque abusa de como o runtime reentra no espaço de processo do contêiner durante o manuseio de exec.

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

CVEs recentes de runtime tais como `CVE-2024-21626` em `runc`, BuildKit mount races, e containerd parsing bugs reforçam o mesmo ponto. A versão do runtime e o nível de patch fazem parte da fronteira de segurança, não meramente trivia de manutenção.
{{#include ../../../banners/hacktricks-training.md}}
