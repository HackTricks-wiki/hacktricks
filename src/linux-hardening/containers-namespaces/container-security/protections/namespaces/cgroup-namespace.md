# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Visão geral

O cgroup namespace não substitui os cgroups nem impõe limites de recursos por si só. Em vez disso, ele altera **como a hierarquia de cgroups aparece** para o processo. Em outras palavras, ele virtualiza as informações visíveis do caminho do cgroup para que a carga de trabalho veja uma visão limitada ao contêiner, em vez de toda a hierarquia do host.

Esse é principalmente um recurso de visibilidade e redução de informações. Ele ajuda a fazer o ambiente parecer autocontido e revela menos informações sobre o layout de cgroups do host. Isso pode parecer algo modesto, mas ainda é importante, pois a visibilidade desnecessária da estrutura do host pode auxiliar no reconhecimento e simplificar cadeias de exploit dependentes do ambiente.

## Operação

Sem um cgroup namespace privado, um processo pode visualizar caminhos de cgroup relativos ao host que expõem mais da hierarquia da máquina do que é necessário. Com um cgroup namespace privado, `/proc/self/cgroup` e observações relacionadas tornam-se mais localizados na própria visão do contêiner. Isso é particularmente útil em stacks modernas de runtime que desejam que a carga de trabalho veja um ambiente mais limpo e que revele menos informações sobre o host.

A virtualização também afeta `/proc/<pid>/mountinfo`, não apenas `/proc/<pid>/cgroup`. Quando você lê outro processo a partir de uma perspectiva de cgroup namespace diferente, os caminhos fora da raiz do seu namespace são exibidos com componentes `../` no início, o que é uma pista útil de que você está examinando acima da sua subárvore delegada. Uma nuance útil para labs e post-exploitation é que um cgroup namespace recém-criado frequentemente precisa de um **cgroupfs remount de dentro desse namespace** antes que `mountinfo` reflita corretamente a nova raiz. Caso contrário, você ainda poderá ver uma raiz de montagem como `/..`, o que significa que a montagem herdada ainda está expondo uma visão baseada na raiz de um ancestral, mesmo que o namespace em si já tenha sido alterado.

## Lab

Você pode inspecionar um cgroup namespace com:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
Se quiser que `mountinfo` mostre mais claramente a nova raiz do cgroup namespace, remonte o sistema de arquivos cgroup de dentro do novo namespace e compare novamente:
```bash
mount --make-rslave /
umount /sys/fs/cgroup 2>/dev/null
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
E compare o comportamento em tempo de execução com:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
A mudança está principalmente relacionada ao que o processo consegue ver, e não à existência ou não de enforcement de cgroup.

## Security Impact

O namespace de cgroup é melhor entendido como uma **camada de hardening de visibilidade**. Por si só, ele não impedirá um breakout se o container tiver mounts de cgroup graváveis, capabilities amplas ou um ambiente cgroup v1 perigoso. No entanto, se o namespace de cgroup do host for compartilhado, o processo descobrirá mais sobre como o sistema está organizado e poderá achar mais fácil relacionar paths de cgroup relativos ao host com outras observações.

No **cgroup v2**, o namespace começa a ser um pouco mais relevante porque as regras de delegation são mais rígidas. Se a hierarquia estiver montada com `nsdelegate`, o kernel tratará os namespaces de cgroup como limites de delegation: os arquivos de controle dos ancestrais devem permanecer fora do alcance do delegatee, e as escritas na raiz do namespace ficam restritas a arquivos seguros para delegation, como `cgroup.procs`, `cgroup.threads` e `cgroup.subtree_control`. Isso ainda não transforma o namespace, por si só, em uma primitive de escape, mas altera o que uma workload comprometida pode inspecionar e onde pode criar sub-cgroups com segurança.

Portanto, embora esse namespace geralmente não seja o destaque em writeups de container breakout, ele ainda contribui para o objetivo mais amplo de minimizar o information leakage do host e restringir a delegation de cgroup.

## Abuse

O valor imediato para abuse é principalmente de reconnaissance. Se o namespace de cgroup do host for compartilhado, compare os paths visíveis e procure detalhes da hierarquia que revelem informações sobre o host:
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
O namespace em si raramente proporciona uma fuga instantânea, mas muitas vezes facilita o mapeamento do ambiente antes de testar primitivas de abuso baseadas em cgroup.

Uma verificação rápida da realidade do runtime também ajuda a priorizar o caminho de ataque. O Docker expõe `--cgroupns=host|private`, enquanto o Podman oferece `host`, `private`, `container:<id>` e `ns:<path>`. Especificamente no Podman, o padrão geralmente é **`host` no cgroup v1** e **`private` no cgroup v2**; portanto, identificar apenas a versão do cgroup já informa qual postura de namespace é mais provável, antes mesmo de inspecionar a configuração OCI completa.

### Reconhecimento moderno de v2: este é um subtree delegado?

Em hosts modernos, a questão interessante geralmente não é `release_agent`, mas sim se o processo atual está dentro de um subtree **cgroup v2** delegado, com visibilidade ou acesso de escrita suficientes para criar grupos aninhados:
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
Interpretação útil:

- `cgroup2fs` significa que você está na hierarquia unificada v2, portanto as chains clássicas exclusivas do v1 com `release_agent` não devem ser sua primeira hipótese.
- `cgroup.controllers` mostra quais controllers estão disponíveis a partir do parent e, portanto, para quais controllers o subtree atual poderia potencialmente criar children.
- `cgroup.subtree_control` mostra quais controllers estão realmente habilitados para os descendants.
- `cgroup.events` expõe `populated=0/1`, o que é útil para observar se um subtree ficou vazio, mas **não** é uma primitive de host-code-execution como o `release_agent` do v1.

Se você já tiver privilégios suficientes para inspecionar diretamente o namespace de outro processo, compare as views com:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### Exemplo completo: Shared cgroup Namespace + Writable cgroup v1

O cgroup namespace, por si só, geralmente não é suficiente para realizar um escape. A escalada prática ocorre quando paths de cgroup que revelam o host são combinados com interfaces writable do cgroup v1:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Se esses arquivos estiverem acessíveis e com permissão de escrita, faça pivot imediatamente para o fluxo completo de exploração de `release_agent` em [cgroups.md](../cgroups.md). O impacto é a execução de código no host a partir de dentro do container.

Sem interfaces cgroup com permissão de escrita, o impacto geralmente fica limitado ao reconnaissance.

## Verificações

O objetivo destes comandos é verificar se o processo tem uma visão privada do namespace cgroup ou se está obtendo mais informações sobre a hierarquia do host do que realmente precisa.
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
O que é interessante aqui:

- Se o identificador do namespace corresponder a um processo do host relevante, o cgroup namespace pode ser compartilhado.
- Caminhos que revelam o host em `/proc/self/cgroup` ou entradas baseadas na raiz de ancestrais em `mountinfo` são úteis para reconhecimento, mesmo quando não são diretamente exploráveis.
- Se `cgroup2fs` estiver em uso, concentre-se em delegation, controllers visíveis e subtrees graváveis, em vez de presumir que os primitivos antigos do v1 ainda existam.
- Se os mounts de cgroup também forem graváveis, a questão da visibilidade se torna muito mais importante.

O cgroup namespace deve ser tratado como uma camada de hardening de visibilidade, e não como um mecanismo primário de prevenção de escape. Expor desnecessariamente a estrutura de cgroups do host acrescenta valor de reconhecimento para o atacante.

## Referências

- [Linux cgroup_namespaces(7)](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [Linux kernel cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
