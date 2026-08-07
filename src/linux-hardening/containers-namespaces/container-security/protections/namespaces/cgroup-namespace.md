# Namespace de cgroup

{{#include ../../../../../banners/hacktricks-training.md}}

## Visão geral

O namespace de cgroup não substitui os cgroups e não impõe limites de recursos por si só. Em vez disso, ele altera **como a hierarquia de cgroups aparece** para o processo. Em outras palavras, ele virtualiza as informações visíveis do caminho do cgroup para que o workload veja uma visão limitada ao container, em vez da hierarquia completa do host.

Esse é principalmente um recurso de visibilidade e redução de informações. Ele ajuda a fazer o ambiente parecer autocontido e revela menos sobre o layout de cgroups do host. Isso pode parecer modesto, mas ainda é importante, pois a visibilidade desnecessária da estrutura do host pode auxiliar no reconhecimento e simplificar exploit chains dependentes do ambiente.

## Operação

Sem um namespace de cgroup privado, um processo pode ver caminhos de cgroup relativos ao host que expõem mais da hierarquia da máquina do que é útil. Com um namespace de cgroup privado, `/proc/self/cgroup` e observações relacionadas tornam-se mais localizados na própria visão do container. Isso é particularmente útil em runtime stacks modernos que desejam que o workload veja um ambiente mais limpo e que revele menos informações sobre o host.

A virtualização também afeta `/proc/<pid>/mountinfo`, não apenas `/proc/<pid>/cgroup`. Quando você lê outro processo a partir de uma perspectiva de namespace de cgroup diferente, os caminhos fora da raiz do seu namespace são exibidos com componentes `../` no início, uma pista útil de que você está olhando acima da sua subtree delegada. Uma nuance útil para labs e post-exploitation é que um namespace de cgroup recém-criado frequentemente precisa de um **cgroupfs remount de dentro desse namespace** antes que `mountinfo` reflita a nova raiz corretamente. Caso contrário, você ainda poderá ver uma mount root como `/..`, o que significa que o mount herdado ainda está expondo uma visão com raiz em um ancestor, mesmo que o namespace em si já tenha sido alterado.<sup>[[1]](#references)</sup>

## Lab

Você pode inspecionar um namespace de cgroup com:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
Se quiser que `mountinfo` mostre a nova root do cgroup-namespace com mais clareza, remonte o sistema de arquivos cgroup de dentro do novo namespace e compare novamente:
```bash
mount --make-rslave /
umount /sys/fs/cgroup 2>/dev/null
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
E compare o comportamento em runtime com:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
A mudança diz respeito principalmente ao que o processo consegue ver, não à existência ou não de enforcement de cgroup.

## Impacto de segurança

O cgroup namespace é melhor entendido como uma **camada de hardening de visibilidade**. Por si só, ele não impedirá um breakout se o container tiver mounts de cgroup graváveis, capabilities amplas ou um ambiente perigoso de cgroup v1. No entanto, se o cgroup namespace do host for compartilhado, o processo obterá mais informações sobre como o sistema está organizado e poderá achar mais fácil associar caminhos de cgroup relativos ao host a outras observações.

No **cgroup v2**, o namespace começa a ter um pouco mais de importância porque as regras de delegation são mais rígidas. Se a hierarquia estiver montada com `nsdelegate`, o kernel trata os cgroup namespaces como limites de delegation: os arquivos de controle ancestrais devem permanecer fora do alcance do delegatee, e as escritas na raiz do namespace ficam restritas a arquivos compatíveis com delegation, como `cgroup.procs`, `cgroup.threads` e `cgroup.subtree_control`.<sup>[[2]](#references)</sup> Isso ainda não transforma o namespace, por si só, em uma primitiva de escape, mas altera o que uma workload comprometida pode inspecionar e onde pode criar sub-cgroups com segurança.

Assim, embora esse namespace normalmente não seja o destaque em writeups de container breakout, ele ainda contribui para o objetivo mais amplo de minimizar o vazamento de informações do host e restringir a delegation de cgroup.

## Abuso

O valor imediato para abuso é principalmente a reconnaissance. Se o cgroup namespace do host for compartilhado, compare os caminhos visíveis e procure detalhes da hierarquia que revelem informações do host:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Se caminhos de cgroup graváveis também estiverem expostos, combine essa visibilidade com uma busca por interfaces legadas perigosas:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
O namespace em si raramente fornece um escape imediato, mas muitas vezes torna o ambiente mais fácil de mapear antes de testar primitives de abuso baseadas em cgroup.

Uma verificação rápida da realidade do runtime também ajuda a priorizar o caminho de ataque. O Docker expõe `--cgroupns=host|private`, enquanto o Podman oferece suporte a `host`, `private`, `container:<id>` e `ns:<path>`. Especificamente no Podman, o padrão geralmente é **`host` no cgroup v1** e **`private` no cgroup v2**; portanto, identificar apenas a versão do cgroup já informa qual postura de namespace é mais provável antes mesmo de você inspecionar a configuração OCI completa.

### Reconhecimento moderno de v2: Este é um Subtree Delegado?

Em hosts modernos, a pergunta interessante geralmente não é `release_agent`, mas se o processo atual está dentro de um subtree **cgroup v2** delegado com visibilidade ou acesso de escrita suficiente para criar grupos aninhados:
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
Interpretação útil:

- `cgroup2fs` significa que você está na hierarquia unificada v2, portanto as chains clássicas `release_agent` exclusivas da v1 não devem ser sua primeira hipótese.
- `cgroup.controllers` mostra quais controllers estão disponíveis no parent e, portanto, para quais controllers o subtree atual poderia potencialmente se ramificar para os children.
- `cgroup.subtree_control` mostra quais controllers estão realmente habilitados para os descendants.
- `cgroup.events` expõe `populated=0/1`, o que é útil para observar se um subtree ficou vazio, mas **não** é uma primitive de execução de código no host como `release_agent` da v1.

Se você já tiver privilégios suficientes para inspecionar diretamente o namespace de outro processo, compare as views com:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### Exemplo completo: Shared cgroup Namespace + Writable cgroup v1

O cgroup namespace, por si só, normalmente não é suficiente para realizar um escape. A escalada prática ocorre quando cgroup paths que revelam o host são combinados com interfaces graváveis do cgroup v1:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Se esses arquivos estiverem acessíveis e forem graváveis, avance imediatamente para o fluxo completo de exploração de `release_agent` em [cgroups.md](../cgroups.md). O impacto é a execução de código no host a partir de dentro do container.

Sem interfaces de cgroup graváveis, o impacto geralmente fica limitado ao reconhecimento.

## Verificações

O objetivo destes comandos é verificar se o processo tem uma visão privada do namespace de cgroup ou se está obtendo mais informações sobre a hierarquia do host do que realmente precisa.
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
O que é interessante aqui:

- Se o identificador do namespace corresponder a um processo do host que seja relevante para você, o cgroup namespace pode ser compartilhado.
- Caminhos que revelam o host em `/proc/self/cgroup` ou entradas baseadas na raiz de ancestrais em `mountinfo` são úteis para reconhecimento, mesmo quando não são diretamente exploráveis.
- Se `cgroup2fs` estiver em uso, concentre-se em delegation, nos controllers visíveis e nas subárvores graváveis, em vez de presumir que as primitivas antigas da v1 ainda existem.
- Se os mounts de cgroup também forem graváveis, a questão da visibilidade se torna muito mais importante.

O cgroup namespace deve ser tratado como uma camada de hardening de visibilidade, e não como um mecanismo primário de prevenção de escape. Expor desnecessariamente a estrutura de cgroup do host acrescenta valor de reconhecimento para o atacante.

## Referências

- [1] [cgroup_namespaces(7) — página do manual do Linux](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [2] [Control Group v2 — documentação do Linux Kernel](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
