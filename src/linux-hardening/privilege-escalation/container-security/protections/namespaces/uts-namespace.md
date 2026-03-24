# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Visão geral

O UTS namespace isola o **hostname** e o **NIS domain name** vistos pelo processo. À primeira vista isso pode parecer trivial comparado com os namespaces mount, PID ou user, mas faz parte do que faz um container parecer ser seu próprio host. Dentro do namespace, a workload pode ver e, às vezes, alterar um hostname que é local a esse namespace em vez de global para a máquina.

Por si só, isto geralmente não é o foco principal de uma história de breakout. No entanto, uma vez que o UTS namespace do host seja compartilhado, um processo com privilégios suficientes pode influenciar configurações relacionadas à identidade do host, o que pode importar operacionalmente e, ocasionalmente, do ponto de vista da segurança.

## Laboratório

Você pode criar um UTS namespace com:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
A mudança do hostname permanece local a esse namespace e não altera o hostname global do host. Esta é uma demonstração simples, mas eficaz, da propriedade de isolamento.

## Uso em tempo de execução

Contêineres normais obtêm um UTS namespace isolado. Docker e Podman podem ingressar no UTS namespace do host através de `--uts=host`, e padrões semelhantes de compartilhamento com o host podem aparecer em outros runtimes e sistemas de orquestração. Na maior parte do tempo, no entanto, o isolamento privado do UTS faz simplesmente parte da configuração normal do contêiner e requer pouca atenção do operador.

## Impacto na Segurança

Apesar de o UTS namespace não ser normalmente o mais perigoso de compartilhar, ele ainda contribui para a integridade da fronteira do contêiner. Se o UTS namespace do host estiver exposto e o processo tiver os privilégios necessários, ele pode ser capaz de alterar informações relacionadas ao hostname do host. Isso pode afetar monitoramento, registro, suposições operacionais ou scripts que tomam decisões de confiança baseadas em dados de identidade do host.

## Abuso

Se o UTS namespace do host for compartilhado, a pergunta prática é se o processo pode modificar as configurações de identidade do host em vez de apenas lê-las:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
Se o container também tiver o privilégio necessário, teste se o hostname pode ser alterado:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
Isso é principalmente um problema de integridade e impacto operacional, em vez de uma fuga completa, mas ainda mostra que o container pode influenciar diretamente uma propriedade global do host.

Impacto:

- adulteração da identidade do host
- confusão em logs, monitoramento ou automações que confiam no hostname
- geralmente não é uma fuga completa por si só, a menos que combinada com outras vulnerabilidades

Em ambientes Docker-style, um padrão útil de detecção no lado do host é:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Containers que mostram `UTSMode=host` estão compartilhando o host UTS namespace e devem ser revisados com mais cuidado se também carregarem capacidades que lhes permitam chamar `sethostname()` ou `setdomainname()`.

## Verificações

Estes comandos são suficientes para ver se a workload tem sua própria visão de hostname ou está compartilhando o host UTS namespace.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
O que é interessante aqui:

- Combinar identificadores de namespace com um processo do host pode indicar que o UTS do host está sendo compartilhado.
- Se alterar o hostname afetar mais do que o próprio container, a workload tem mais influência sobre a identidade do host do que deveria.
- Isto geralmente é um achado de menor prioridade do que problemas de PID, mount ou user namespace, mas ainda confirma o quão isolado o processo realmente está.

Na maioria dos ambientes, o UTS namespace deve ser considerado como uma camada de isolamento de suporte. Raramente é a primeira coisa que você persegue em um breakout, mas ainda faz parte da consistência e segurança geral da visão do container.
{{#include ../../../../../banners/hacktricks-training.md}}
