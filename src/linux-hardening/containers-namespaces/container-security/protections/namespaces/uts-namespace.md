# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Visão geral

O UTS namespace isola o **hostname** e o **NIS domain name** vistos pelo processo. À primeira vista, isso pode parecer trivial em comparação com mount, PID ou user namespaces, mas ele faz parte do que faz um container parecer ser seu próprio host. Dentro do namespace, o workload pode visualizar e, às vezes, alterar um hostname local a esse namespace, em vez de global à máquina.

Por si só, isso geralmente não é o ponto central de uma história de breakout. No entanto, quando o host UTS namespace é compartilhado, um processo com privilégios suficientes pode influenciar configurações relacionadas à identidade do host, o que pode ser relevante operacionalmente e, ocasionalmente, do ponto de vista de segurança.

## Lab

Você pode criar um UTS namespace com:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
A alteração do hostname permanece local a esse namespace e não altera o hostname global do host. Esta é uma demonstração simples, mas eficaz, da propriedade de isolamento.

## Uso em Runtime

Containers normais obtêm um namespace UTS isolado. Docker e Podman podem ingressar no namespace UTS do host por meio de `--uts=host`, e padrões semelhantes de compartilhamento do host podem aparecer em outros runtimes e sistemas de orquestração. Na maior parte do tempo, porém, o isolamento UTS privado é simplesmente parte da configuração normal do container e requer pouca atenção do operador.

## Impacto de Segurança

Embora o namespace UTS normalmente não seja o mais perigoso de compartilhar, ele ainda contribui para a integridade da fronteira do container. Se o namespace UTS do host estiver exposto e o processo tiver os privilégios necessários, ele poderá alterar informações relacionadas ao hostname do host. Isso pode afetar o monitoramento, os logs, as suposições operacionais ou scripts que tomam decisões de confiança com base em dados de identidade do host.

## Abuso

Se o namespace UTS do host for compartilhado, a questão prática é saber se o processo pode modificar as configurações de identidade do host, em vez de apenas lê-las:
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
Este é principalmente um problema de integridade e impacto operacional, e não um escape completo, mas ainda demonstra que o container pode influenciar diretamente uma propriedade global do host.

Impacto:

- adulteração da identidade do host
- logs, monitoramento ou automação confusos que confiam no hostname
- geralmente não é um escape completo por si só, a menos que seja combinado com outras vulnerabilidades

Em ambientes no estilo Docker, um padrão útil de detecção no host é:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Containers que mostram `UTSMode=host` estão compartilhando o namespace UTS do host e devem ser revisados com mais atenção caso também tenham capabilities que permitam chamar `sethostname()` ou `setdomainname()`.

## Verificações

Estes comandos são suficientes para verificar se o workload tem sua própria visão do hostname ou se está compartilhando o namespace UTS do host.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
O que é interessante aqui:

- Identificadores de namespace correspondentes aos de um processo do host podem indicar o compartilhamento do UTS namespace com o host.
- Se alterar o hostname afetar mais do que o próprio container, o workload terá mais influência sobre a identidade do host do que deveria.
- Normalmente, essa é uma descoberta de prioridade inferior à de problemas no PID, mount ou user namespace, mas ainda confirma o grau real de isolamento do processo.

Na maioria dos ambientes, o UTS namespace deve ser considerado uma camada de isolamento complementar. Raramente é a primeira coisa investigada em um breakout, mas ainda faz parte da consistência geral e da segurança da visão do container.
{{#include ../../../../../banners/hacktricks-training.md}}
