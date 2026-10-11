# Runtimes, Engines, Builders E Sandboxes De Containers

{{#include ../../../banners/hacktricks-training.md}}

Uma das maiores fontes de confusão na segurança de containers é que vários componentes completamente diferentes costumam ser agrupados sob a mesma palavra. “Docker” pode se referir a um formato de imagem, uma CLI, um daemon, um sistema de build, uma pilha de runtime ou simplesmente à ideia de containers em geral. Para o trabalho de segurança, essa ambiguidade é um problema, porque diferentes camadas são responsáveis por diferentes proteções. Um escape causado por um bind mount mal configurado não é o mesmo que um escape causado por um bug no runtime de baixo nível, e nenhum dos dois é igual a um erro na política de cluster do Kubernetes.

Esta página separa o ecossistema por função para que o restante da seção possa explicar com precisão onde uma proteção ou vulnerabilidade realmente se encontra.

## OCI Como Linguagem Comum

As pilhas modernas de containers Linux costumam interoperar porque seguem um conjunto de especificações OCI. A **OCI Image Specification** descreve como as imagens e camadas são representadas. A **OCI Runtime Specification** descreve como o runtime deve iniciar o processo, incluindo namespaces, mounts, cgroups e configurações de segurança. A **OCI Distribution Specification** padroniza como os registries disponibilizam conteúdo.

Isso importa porque explica por que uma imagem de container criada com uma ferramenta muitas vezes pode ser executada com outra, e por que vários engines podem compartilhar o mesmo runtime de baixo nível. Também explica por que o comportamento de segurança pode parecer semelhante em diferentes produtos: muitos deles constroem a mesma configuração de runtime OCI e a entregam ao mesmo pequeno conjunto de runtimes.

## Runtimes OCI De Baixo Nível

O runtime de baixo nível é o componente mais próximo da fronteira com o kernel. É a parte que realmente cria namespaces, grava configurações de cgroup, aplica capabilities e filtros seccomp e, por fim, executa `execve()` para iniciar o processo do container. Quando as pessoas discutem “isolamento de containers” no nível mecânico, geralmente estão falando dessa camada, mesmo que não o digam explicitamente.

### `runc`

`runc` é o runtime OCI de referência e continua sendo a implementação mais conhecida. É muito usado com Docker, containerd e muitas implantações de Kubernetes. Grande parte das pesquisas públicas e do material de exploração mira ambientes do tipo `runc` simplesmente porque são comuns e porque `runc` define a referência que muitas pessoas imaginam quando pensam em um container Linux. Portanto, entender `runc` dá ao leitor um modelo mental sólido do isolamento clássico de containers.

### `crun`

`crun` é outro runtime OCI, escrito em C e amplamente usado em ambientes modernos com Podman. Costuma ser elogiado pelo bom suporte a cgroup v2, pela praticidade para uso rootless e pelo menor overhead. Do ponto de vista da segurança, o importante não é que ele seja escrito em outra linguagem, mas que desempenha a mesma função: transformar a configuração OCI em uma árvore de processos em execução sob o kernel. Um fluxo de trabalho rootless com Podman muitas vezes parece mais seguro não porque `crun` resolva magicamente todos os problemas, mas porque a pilha ao redor tende a priorizar namespaces de usuário e least privilege.

### `runsc` Do gVisor

`runsc` é o runtime usado pelo gVisor. Aqui, a fronteira muda significativamente. Em vez de passar a maioria das syscalls diretamente ao kernel do host da maneira habitual, o gVisor insere uma camada de kernel em userspace que emula ou intermedeia grande parte da interface Linux. O resultado não é um container `runc` normal com algumas flags extras; é um design de sandbox diferente, cujo objetivo é reduzir a superfície de ataque do kernel do host. Compromissos entre compatibilidade e desempenho fazem parte desse design, então ambientes que usam `runsc` devem ser documentados de forma diferente dos ambientes com runtimes OCI normais.

### `kata-runtime`

Kata Containers vão além ao iniciar a workload dentro de uma máquina virtual leve. Do ponto de vista administrativo, ainda pode parecer uma implantação de container, e as camadas de orquestração ainda podem tratá-la como tal, mas a fronteira de isolamento subjacente se aproxima mais da virtualização do que de um container clássico que compartilha o kernel do host. Isso torna o Kata útil quando se deseja um isolamento mais forte entre tenants sem abandonar os fluxos de trabalho centrados em containers.

## Engines E Gerenciadores De Containers

Se o runtime de baixo nível é o componente que se comunica diretamente com o kernel, o engine ou gerenciador é o componente com que usuários e operadores costumam interagir. Ele gerencia pulls de imagens, metadados, logs, redes, volumes, operações de ciclo de vida e exposição de APIs. Essa camada é extremamente importante porque muitos comprometimentos reais acontecem aqui: o acesso a um socket de runtime ou à API do daemon pode equivaler ao comprometimento do host, mesmo que o próprio runtime de baixo nível esteja funcionando perfeitamente.

### Docker Engine

Docker Engine é a plataforma de containers mais reconhecida pelos desenvolvedores e uma das razões pelas quais o vocabulário de containers se tornou tão associado ao Docker. O fluxo típico é a CLI `docker` se comunicar com `dockerd`, que por sua vez coordena componentes de nível inferior, como `containerd` e um runtime OCI. Historicamente, as implantações Docker costumam ser **rootful**, e, portanto, o acesso ao socket do Docker é uma primitiva muito poderosa. Por isso, tanto material prático sobre privilege escalation se concentra em `docker.sock`: se um processo puder pedir ao `dockerd` que crie um container privilegiado, monte caminhos do host ou entre em namespaces do host, talvez nem precise de um exploit de kernel.

Compare os números de versão por componentes major, minor e patch, em vez de remover os pontos: `18.09.1` é anterior a `18.09.2` e `18.09.4`, apesar do componente minor preenchido com zero. As [notas de lançamento da versão 18.09 do Docker](https://docs.docker.com/engine/release-notes/18.09/) registram a correção de `runc` incluída para CVE-2019-5736 na versão 18.09.2 e a correção de build-reference para CVE-2019-13139 na versão 18.09.4. Essas versões são pistas, não provas de que um exploit seja alcançável. As mesmas notas alertam que o daemon, o cliente e o runtime são empacotados separadamente; portanto, verifique o runtime instalado e os backports do fornecedor além da versão do daemon. Um problema de build-reference também exige acesso ao fluxo de build afetado e entrada controlada pelo atacante.

### Podman

O Podman foi projetado em torno de um modelo mais daemonless. Do ponto de vista operacional, isso ajuda a reforçar a ideia de que containers são apenas processos gerenciados por mecanismos Linux padrão, e não por um único daemon privilegiado de longa duração. O Podman também oferece uma abordagem **rootless** muito mais sólida do que as implantações clássicas do Docker que muitas pessoas conheceram primeiro. Isso não torna o Podman automaticamente seguro, mas altera significativamente o perfil de risco padrão, especialmente quando combinado com namespaces de usuário, SELinux e `crun`.

### containerd

containerd é um componente central de gerenciamento de runtimes em muitas pilhas modernas. É usado com Docker e também é um dos backends de runtime dominantes no Kubernetes. Ele expõe APIs poderosas, gerencia imagens e snapshots e delega a criação final do processo a um runtime de baixo nível. As discussões de segurança sobre containerd devem enfatizar que o acesso ao socket do containerd ou às funcionalidades de `ctr`/`nerdctl` pode ser tão perigoso quanto o acesso à API do Docker, mesmo que a interface e o fluxo de trabalho pareçam menos “amigáveis para desenvolvedores”.

### CRI-O

CRI-O tem um escopo mais específico que o Docker Engine. Em vez de ser uma plataforma de desenvolvimento de uso geral, foi criado para implementar de forma clara a Kubernetes Container Runtime Interface. Isso o torna especialmente comum em distribuições Kubernetes e ecossistemas que usam bastante SELinux, como o OpenShift. Do ponto de vista da segurança, esse escopo mais restrito é útil porque reduz a confusão conceitual: CRI-O faz parte claramente da camada de “execução de containers para Kubernetes”, em vez de ser uma plataforma que faz tudo.

Quando um nó Kubernetes usa CRI-O, verifique a **versão ativa do CRI-O no nó** e se a identidade atual pode criar Pods em um namespace agendado nesse nó. [CVE-2022-0811](https://github.com/cri-o/cri-o/security/advisories/GHSA-6x2m-w449-qwx7) permitia que valores de sysctl especialmente criados em um Pod alterassem um parâmetro do kernel do host e possibilitassem execução como root no host nas versões afetadas. O aviso upstream lista as versões corrigidas e as soluções alternativas. Um `crio --version` local pode não identificar um runtime aninhado no Minikube ou em outro container de nó; um log de inicialização legível do Minikube pode fornecer uma pista sobre a versão, mas é evidência histórica, não prova do runtime ativo nem do estado das correções. Confirme o runtime real do nó, a autorização para criar Pods, as regras de admission e as fronteiras relevantes de seccomp e namespaces de usuário antes de considerar isso uma escalada alcançável.

Há também um caminho direto de análise local do `pinns`: os [pesquisadores observam que não é necessário Kubernetes para invocar o helper vulnerável](https://www.crowdstrike.com/en-us/blog/cr8escape-new-vulnerability-discovered-in-cri-o-container-engine-cve-2022-0811/). Verifique se a conta atual pode executar um `pinns` com setuid pertencente ao root, se NoNewPrivs ou um mount `nosuid` bloqueia essa transição e se o **build do helper** instalado não contém a correção. O [aviso upstream](https://github.com/cri-o/cri-o/security/advisories/GHSA-6x2m-w449-qwx7) lista as versões corrigidas, mas a versão exibida por um daemon, por si só, não prova qual binário helper está instalado; além disso, backports dos distribuidores podem alterar a exposição. Um arquivo setuid é apenas um candidato; valide a procedência do helper, a configuração e o comportamento do sysctl do host sem executá-lo durante uma enumeração de rotina.

### Incus, LXD E LXC

Vale a pena distinguir os sistemas Incus/LXD/LXC dos containers de aplicações no estilo Docker, pois eles costumam ser usados como **system containers**. Em geral, espera-se que um system container se pareça mais com uma máquina leve, com um userspace mais completo, serviços de longa duração, maior exposição de dispositivos e integração mais abrangente com o host. Os mecanismos de isolamento ainda são primitivas do kernel, mas as expectativas operacionais são diferentes. Por isso, as configurações incorretas aqui costumam se parecer menos com “padrões ruins para containers de aplicações” e mais com erros de virtualização leve ou de delegação do host.

### systemd-nspawn

systemd-nspawn ocupa uma posição interessante porque é nativo do systemd e muito útil para testes, debugging e execução de ambientes semelhantes a sistemas operacionais. Não é o runtime de produção cloud-native dominante, mas aparece com frequência suficiente em laboratórios e ambientes voltados a distribuições para merecer menção. Para a análise de segurança, é mais um lembrete de que o conceito de “container” abrange vários ecossistemas e estilos operacionais.

### Apptainer / Singularity

Apptainer (antigo Singularity) é comum em ambientes de pesquisa e HPC. Suas premissas de confiança, fluxo de trabalho do usuário e modelo de execução diferem de maneiras importantes das pilhas centradas em Docker/Kubernetes. Em particular, esses ambientes costumam dar muita importância a permitir que os usuários executem workloads empacotadas sem lhes conceder amplos poderes privilegiados de gerenciamento de containers. Se um revisor presumir que todo ambiente de containers é basicamente “Docker em um servidor”, entenderá muito mal essas implantações.

## Ferramentas De Build

Muitas discussões de segurança falam apenas do runtime, mas as ferramentas de build também importam, pois determinam o conteúdo das imagens, a exposição de secrets durante o build e quanto contexto confiável é incorporado ao artefato final.

**BuildKit** e `docker buildx` são backends de build modernos que oferecem recursos como caching, montagem de secrets, encaminhamento de SSH e builds multiplataforma. Esses recursos são úteis, mas, do ponto de vista da segurança, também criam pontos onde secrets podem vazar para as camadas da imagem ou onde um contexto de build excessivamente amplo pode expor arquivos que nunca deveriam ter sido incluídos. **Buildah** desempenha uma função semelhante em ecossistemas nativos de OCI, especialmente com Podman, enquanto **Kaniko** costuma ser usado em ambientes de CI que não querem conceder um daemon Docker privilegiado ao pipeline de build.

A principal lição é que a criação e a execução de imagens são fases diferentes, mas um pipeline de build fraco pode comprometer a postura de segurança do runtime muito antes de o container ser iniciado.

## Orquestração É Outra Camada, Não O Runtime

O Kubernetes não deve ser mentalmente equiparado ao próprio runtime. Kubernetes é o orquestrador. Ele agenda Pods, armazena o estado desejado e expressa políticas de segurança por meio da configuração das workloads. Então o kubelet se comunica com uma implementação de CRI, como containerd ou CRI-O, que por sua vez invoca um runtime de baixo nível, como `runc`, `crun`, `runsc` ou `kata-runtime`.

Essa separação importa porque muitas pessoas atribuem incorretamente uma proteção ao “Kubernetes” quando, na verdade, ela é aplicada pelo runtime do nó, ou culpam os “padrões do containerd” por um comportamento que veio da especificação do Pod. Na prática, a postura de segurança final é uma composição: o orquestrador solicita algo, a pilha de runtime traduz essa solicitação e, por fim, o kernel a aplica.

## Por Que Identificar O Runtime Importa Durante Uma Avaliação

Se você identificar o engine e o runtime logo no início, será mais fácil interpretar muitas observações posteriores. Um container Podman rootless sugere que namespaces de usuário provavelmente fazem parte do cenário. Um socket Docker montado em uma workload sugere que uma privilege escalation por meio de API é um caminho realista. Um nó CRI-O/OpenShift deve fazer você pensar imediatamente em labels do SELinux e políticas restritivas de workload. Um ambiente gVisor ou Kata deve fazer você ter mais cautela antes de presumir que um PoC clássico de escape de `runc` terá o mesmo comportamento.

Por isso, uma das primeiras etapas de uma avaliação de containers deve ser sempre responder a duas perguntas simples: **qual componente gerencia o container** e **qual runtime realmente iniciou o processo**. Quando essas respostas estiverem claras, normalmente fica muito mais fácil analisar o restante do ambiente.

## Vulnerabilidades De Runtime

Nem todo escape de container é causado por uma configuração incorreta do operador. Às vezes, o próprio runtime é o componente vulnerável. Isso importa porque uma workload pode estar sendo executada com uma configuração aparentemente cuidadosa e ainda assim estar exposta a uma falha de runtime de baixo nível.

O exemplo clássico é a **CVE-2019-5736** no `runc`, em que um container malicioso podia sobrescrever o binário `runc` do host e então aguardar uma chamada posterior a `docker exec` ou uma invocação semelhante do runtime para executar código controlado pelo atacante. O caminho de exploração é bem diferente de um simples erro de bind mount ou de capabilities porque abusa da forma como o runtime volta a entrar no espaço de processos do container durante o tratamento de `exec`.<sup>[[1]](#references)</sup>

Um fluxo mínimo de reprodução do ponto de vista de uma equipe red team é:

```bash
go build main.go
./main
```

Em seguida, a partir do host:

```bash
docker exec -it <container-name> /bin/sh
```

A principal lição não é a implementação exata do exploit histórico, mas a implicação para a avaliação: se a versão do runtime for vulnerável, a execução comum de código dentro do container pode ser suficiente para comprometer o host, mesmo quando a configuração visível do container não parece obviamente fraca.

CVEs recentes de runtime, como `CVE-2024-21626` no `runc`, condições de corrida em mounts do BuildKit e bugs de parsing do containerd reforçam o mesmo ponto. A versão e o nível de patch do runtime fazem parte da fronteira de segurança, não são meros detalhes de manutenção.

## References

- [1] [Escaping do Docker via runC – explicando CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
{{#include ../../../banners/hacktricks-training.md}}
