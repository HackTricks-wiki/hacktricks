# Namespace do cgroup

{{#include ../../../../../banners/hacktricks-training.md}}

## Visão geral

O namespace cgroup não substitui cgroups e não impõe limites de recursos por si só. Em vez disso, ele altera **como a hierarquia de cgroup aparece** para o processo. Em outras palavras, ele virtualiza as informações do caminho de cgroup visíveis para que a carga de trabalho veja uma visão com escopo de container em vez da hierarquia completa do host.

Isso é principalmente uma funcionalidade de visibilidade e redução de informação. Ajuda a fazer o ambiente parecer autocontido e revela menos sobre o layout de cgroup do host. Isso pode parecer modesto, mas ainda importa porque visibilidade desnecessária sobre a estrutura do host pode auxiliar reconhecimento e simplificar cadeias de exploração dependentes do ambiente.

## Funcionamento

Sem um namespace de cgroup privado, um processo pode ver caminhos de cgroup relativos ao host que expõem mais da hierarquia da máquina do que é útil. Com um namespace de cgroup privado, /proc/self/cgroup e observações relacionadas tornam-se mais localizadas à visão do próprio container. Isto é particularmente útil em stacks de runtime modernos que querem que a carga de trabalho veja um ambiente mais limpo, que revele menos do host.

## Laboratório

Você pode inspecionar um namespace de cgroup com:
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
A mudança diz respeito principalmente ao que o processo pode ver, não sobre se cgroup enforcement existe.

## Impacto de Segurança

O cgroup namespace é melhor entendido como uma **camada de hardening de visibilidade**. Por si só, não impedirá um breakout se o container tiver writable cgroup mounts, broad capabilities, ou um ambiente cgroup v1 perigoso. Contudo, se o host cgroup namespace for compartilhado, o processo passa a saber mais sobre como o sistema está organizado e pode achar mais fácil alinhar host-relative cgroup paths com outras observações.

Portanto, embora este namespace normalmente não seja a estrela dos container breakout writeups, ele ainda contribui para o objetivo mais amplo de minimizar host information leakage.

## Abuso

O valor imediato de abuso é principalmente reconnaissance. Se o host cgroup namespace for compartilhado, compare os caminhos visíveis e procure por detalhes da hierarquia que revelem o host:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
```
Se caminhos do cgroup graváveis também estiverem expostos, combine essa visibilidade com uma busca por interfaces legadas perigosas:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
A própria namespace raramente dá um escape instantâneo, mas frequentemente facilita mapear o ambiente antes de testar primitivas de abuso baseadas em cgroup.

### Exemplo completo: Shared cgroup Namespace + Writable cgroup v1

A cgroup namespace por si só geralmente não é suficiente para escape. A escalada prática acontece quando caminhos de cgroup que revelam o host são combinados com interfaces cgroup v1 graváveis:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Se esses arquivos estiverem acessíveis e graváveis, pivot imediatamente para o fluxo completo de exploração `release_agent` em [cgroups.md](../cgroups.md). O impacto é execução de código no host a partir de dentro do container.

Sem cgroup interfaces graváveis, o impacto geralmente se limita ao reconhecimento.

## Verificações

O objetivo desses comandos é verificar se o processo tem uma visão privada do cgroup namespace ou está obtendo mais informações sobre a hierarquia do host do que realmente precisa.
```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```
O que é interessante aqui:

- Se o identificador do namespace corresponder a um processo do host que lhe interessa, o cgroup namespace pode ser compartilhado.
- Caminhos que revelam o host em `/proc/self/cgroup` são úteis para reconhecimento mesmo quando não são diretamente exploráveis.
- Se os cgroup mounts também forem graváveis, a questão da visibilidade torna-se muito mais importante.

O cgroup namespace deve ser tratado como uma camada de endurecimento da visibilidade em vez de um mecanismo primário de prevenção de escape. Expor desnecessariamente a estrutura de cgroup do host adiciona valor de reconhecimento para o atacante.
