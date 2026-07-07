# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Visão geral

O cgroup namespace não substitui cgroups e não impõe limites de recursos por si só. Em vez disso, ele muda **como a hierarquia de cgroup aparece** para o processo. Em outras palavras, ele virtualiza as informações visíveis do caminho do cgroup para que a workload veja uma visão limitada ao container, em vez da hierarquia completa do host.

Isso é principalmente um recurso de visibilidade e redução de informações. Ele ajuda a fazer o ambiente parecer autônomo e revela menos sobre a estrutura de cgroup do host. Isso pode parecer modesto, mas ainda importa porque visibilidade desnecessária da estrutura do host pode ajudar na reconnaissance e simplificar cadeias de exploit dependentes do ambiente.

## Operação

Sem um private cgroup namespace, um processo pode ver caminhos de cgroup relativos ao host que expõem mais da hierarquia da máquina do que é útil. Com um private cgroup namespace, `/proc/self/cgroup` e observações relacionadas ficam mais localizadas para a própria visão do container. Isso é particularmente útil em modern runtime stacks que querem que a workload veja um ambiente mais limpo e menos revelador do host.

A virtualização também afeta `/proc/<pid>/mountinfo`, não apenas `/proc/<pid>/cgroup`. Quando você lê outro processo a partir de uma perspectiva de cgroup-namespace diferente, os caminhos fora da raiz do seu namespace são mostrados com componentes `../` à esquerda, o que é uma pista útil de que você está olhando acima da sua subtree delegada. Um detalhe útil para labs e post-exploitation é que um cgroup namespace recém-criado muitas vezes precisa de um **cgroupfs remount de dentro desse namespace** antes que `mountinfo` reflita a nova raiz corretamente. Caso contrário, você ainda pode ver uma mount root como `/..`, o que significa que o mount herdado ainda está expondo uma visão enraizada em um ancestral, mesmo que o namespace em si já tenha mudado.

## Lab

Você pode inspecionar um cgroup namespace com:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
Se você quiser que `mountinfo` mostre a nova raiz do cgroup-namespace com mais clareza, remonte o filesystem cgroup de dentro do novo namespace e compare novamente:
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
A mudança é principalmente sobre o que o processo pode ver, e não sobre se a aplicação de cgroup existe.

## Security Impact

O cgroup namespace é melhor entendido como uma **camada de hardening de visibilidade**. Por si só, ele não vai impedir uma breakout se o container tiver mounts de cgroup graváveis, capabilities amplas ou um ambiente cgroup v1 perigoso. No entanto, se o host cgroup namespace for compartilhado, o processo aprende mais sobre como o sistema está organizado e pode achar mais fácil correlacionar caminhos de cgroup relativos ao host com outras observações.

No **cgroup v2**, o namespace passa a importar um pouco mais porque as regras de delegation são mais rígidas. Se a hierarchy estiver montada com `nsdelegate`, o kernel trata os cgroup namespaces como limites de delegation: os control files ancestrais devem ficar fora do alcance do delegatee, e as gravações na raiz do namespace ficam restritas a arquivos seguros para delegation, como `cgroup.procs`, `cgroup.threads` e `cgroup.subtree_control`. Isso ainda não faz do namespace um primitive de escape por si só, mas muda o que uma workload comprometida pode inspecionar e onde ela pode criar sub-cgroups com segurança.

Então, embora esse namespace normalmente não seja a estrela dos writeups de container breakout, ele ainda contribui para o objetivo mais amplo de minimizar o vazamento de informação do host e restringir a delegation de cgroup.

## Abuse

O valor de abuso imediato é, em grande parte, reconnaissance. Se o host cgroup namespace for compartilhado, compare os paths visíveis e procure detalhes de hierarchy que revelem o host:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Se caminhos cgroup graváveis também estiverem expostos, combine essa visibilidade com uma busca por interfaces legadas perigosas:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
O namespace em si raramente dá escape instantâneo, mas frequentemente torna o ambiente mais fácil de mapear antes de testar primitivas de abuso baseadas em cgroup.

Uma verificação rápida da realidade em runtime também ajuda a priorizar a rota de ataque. O Docker expõe `--cgroupns=host|private`, enquanto o Podman suporta `host`, `private`, `container:<id>` e `ns:<path>`. No Podman especificamente, o padrão costuma ser **`host` em cgroup v1** e **`private` em cgroup v2**, então identificar apenas a versão do cgroup já indica qual postura de namespace é mais provável antes mesmo de inspecionar a configuração completa do OCI.

### Modern v2 Recon: Is This A Delegated Subtree?

Em hosts modernos, a questão interessante frequentemente não é `release_agent`, mas sim se o processo atual está dentro de uma subtree delegada de **cgroup v2** com visibilidade ou acesso de escrita suficientes para criar grupos aninhados:
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
Interpretação útil:

- `cgroup2fs` significa que você está na hierarquia unificada v2, então cadeias clássicas apenas de v1 com `release_agent` devem deixar de ser sua primeira hipótese.
- `cgroup.controllers` mostra quais controllers estão disponíveis a partir do pai e, portanto, para quais o subtree atual poderia potencialmente se ramificar para filhos.
- `cgroup.subtree_control` mostra quais controllers estão realmente habilitados para descendentes.
- `cgroup.events` expõe `populated=0/1`, o que é útil para observar se um subtree ficou vazio, mas **não** é um primitive de execução de código no host como `release_agent` do v1.

Se você já tiver privilégio suficiente para inspecionar diretamente o namespace de outro processo, compare as visões com:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### Exemplo Completo: Shared cgroup Namespace + Writable cgroup v1

O cgroup namespace sozinho geralmente não é suficiente para escape. A escalada prática acontece quando caminhos de cgroup que revelam o host são combinados com interfaces writable de cgroup v1:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Se esses arquivos estiverem acessíveis e graváveis, faça pivot imediatamente para o fluxo completo de exploração de `release_agent` de [cgroups.md](../cgroups.md). O impacto é execução de código no host a partir de dentro do container.

Sem interfaces cgroup graváveis, o impacto geralmente fica limitado a reconnaissance.

## Checks

O objetivo destes comandos é ver se o processo tem uma visão privada do cgroup namespace ou se está aprendendo mais sobre a hierarquia do host do que realmente precisa.
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
O que é interessante aqui:

- Se o identificador do namespace corresponder a um processo do host que você se importa, o cgroup namespace pode ser compartilhado.
- Caminhos que revelam o host em `/proc/self/cgroup` ou entradas enraizadas na raiz ancestral em `mountinfo` são úteis para reconnaissance, mesmo quando não são diretamente exploráveis.
- Se `cgroup2fs` estiver em uso, foque em delegation, controllers visíveis e subtrees graváveis em vez de assumir que os antigos primitives v1 ainda existem.
- Se os mounts de cgroup também forem graváveis, a questão da visibilidade se torna muito mais importante.

O cgroup namespace deve ser tratado como uma camada de visibility-hardening, e não como um mecanismo principal de prevenção de escape. Expor desnecessariamente a estrutura de cgroup do host adiciona valor de reconnaissance para o atacante.

## References

- [Linux cgroup_namespaces(7)](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [Linux kernel cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
