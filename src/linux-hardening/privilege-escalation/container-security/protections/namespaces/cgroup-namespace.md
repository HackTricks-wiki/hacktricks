# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Visão geral

O cgroup namespace não substitui os cgroups e não aplica limites de recursos por si só. Em vez disso, altera **como a hierarquia de cgroups aparece** para o processo. Em outras palavras, ele virtualiza as informações visíveis do caminho de cgroup para que a carga de trabalho veja uma visão com escopo de container em vez da hierarquia completa do host.

Isso é sobretudo uma funcionalidade de visibilidade e redução de informação. Ajuda a fazer o ambiente parecer autocontido e revela menos sobre o layout de cgroups do host. Pode parecer modesto, mas ainda importa, porque visibilidade desnecessária da estrutura do host pode auxiliar o recon e simplificar cadeias de exploit dependentes do ambiente.

## Operação

Sem um cgroup namespace privado, um processo pode ver caminhos de cgroup relativos ao host que expõem mais da hierarquia da máquina do que é útil. Com um cgroup namespace privado, `/proc/self/cgroup` e observações relacionadas tornam-se mais localizadas à visão do próprio container. Isso é especialmente útil em stacks de runtime modernos que querem que a carga de trabalho veja um ambiente mais limpo, que revele menos o host.

## Laboratório

Você pode inspecionar um cgroup namespace com:
```bash
sudo unshare --cgroup --fork bash
cat /proc/self/cgroup
ls -l /proc/self/ns/cgroup
```
E compare o comportamento em tempo de execução com:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
A mudança diz respeito principalmente ao que o processo pode ver, não a se a cgroup enforcement existe.

## Impacto de Segurança

O cgroup namespace é mais bem entendido como uma **camada de hardening de visibilidade**. Por si só, não impedirá um container breakout se o container tiver writable cgroup mounts, broad capabilities, ou um ambiente perigoso de cgroup v1. No entanto, se o host cgroup namespace for compartilhado, o processo passa a saber mais sobre como o sistema está organizado e pode achar mais fácil alinhar host-relative cgroup paths com outras observações.

Então, embora este namespace normalmente não seja a estrela das writeups de container breakout, ele ainda contribui para o objetivo mais amplo de minimizar a exposição de informações do host.

## Abuso

O valor de abuso imediato é principalmente reconhecimento. Se o host cgroup namespace estiver compartilhado, compare os caminhos visíveis e procure por detalhes de hierarquia que revelem o host:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
```
Se caminhos de cgroup graváveis também estiverem expostos, combine essa visibilidade com uma busca por interfaces legadas perigosas:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
O namespace por si só raramente dá escape instantâneo, mas frequentemente torna o ambiente mais fácil de mapear antes de testar cgroup-based abuse primitives.

### Exemplo completo: Shared cgroup Namespace + Writable cgroup v1

O cgroup namespace sozinho geralmente não é suficiente para escape. A escalada prática acontece quando host-revealing cgroup paths são combinados com writable cgroup v1 interfaces:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Se esses arquivos forem acessíveis e graváveis, pivot imediatamente para o full `release_agent` exploitation flow descrito em [cgroups.md](../cgroups.md). O impacto é execução de código no host a partir do interior do container.

Sem interfaces cgroup graváveis, o impacto normalmente fica limitado ao reconhecimento.

## Verificações

O objetivo desses comandos é verificar se o processo tem uma visão privada do cgroup namespace ou se está coletando mais informações sobre a hierarquia do host do que realmente precisa.
```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```
O que é interessante aqui:

- Se o identificador do namespace corresponder a um processo do host que lhe interessa, o cgroup namespace pode ser compartilhado.
- Caminhos em `/proc/self/cgroup` que revelam o host são úteis para reconhecimento mesmo quando não são diretamente exploráveis.
- Se os pontos de montagem de cgroup também forem graváveis, a questão da visibilidade torna-se muito mais importante.

O cgroup namespace deve ser tratado como uma camada de endurecimento da visibilidade em vez de um mecanismo primário de prevenção de escape. Expor desnecessariamente a estrutura de cgroup do host adiciona valor de reconhecimento para o atacante.
{{#include ../../../../../banners/hacktricks-training.md}}
