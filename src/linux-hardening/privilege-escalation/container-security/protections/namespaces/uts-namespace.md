# Namespace UTS

{{#include ../../../../../banners/hacktricks-training.md}}

## Visão geral

O UTS namespace isola o **hostname** e o **NIS domain name** vistos pelo processo. À primeira vista isso pode parecer trivial comparado com mount, PID, or user namespaces, mas faz parte do que faz um container parecer ser seu próprio host. Dentro do namespace, a carga de trabalho pode ver e às vezes alterar um hostname que é local a esse namespace em vez de global para a máquina.

Por si só, isso normalmente não é o centro de uma história de breakout. No entanto, uma vez que o UTS namespace do host é compartilhado, um processo com privilégios suficientes pode influenciar configurações relacionadas à identidade do host, o que pode importar operacionalmente e, ocasionalmente, do ponto de vista de segurança.

## Lab

Você pode criar um namespace UTS com:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
A alteração do hostname permanece local a esse namespace e não altera o hostname global do host. Esta é uma demonstração simples mas eficaz da propriedade de isolamento.

## Uso em tempo de execução

Containers normais recebem um UTS namespace isolado. Docker e Podman podem ingressar no UTS namespace do host através de `--uts=host`, e padrões semelhantes de compartilhamento com o host podem aparecer em outros runtimes e sistemas de orquestração. Na maioria das vezes, entretanto, o isolamento UTS privado é simplesmente parte da configuração normal do container e requer pouca atenção do operador.

## Impacto na segurança

Mesmo que o UTS namespace não seja geralmente o mais perigoso de compartilhar, ele ainda contribui para a integridade da fronteira do container. Se o UTS namespace do host estiver exposto e o processo tiver os privilégios necessários, ele pode ser capaz de alterar informações relacionadas ao hostname do host. Isso pode afetar monitoramento, registros, pressuposições operacionais ou scripts que tomam decisões de confiança com base em dados de identidade do host.

## Abuso

Se o UTS namespace do host for compartilhado, a questão prática é se o processo pode modificar as configurações de identidade do host em vez de apenas lê-las:
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
Isso é principalmente um problema de integridade e impacto operacional em vez de um full escape, mas ainda mostra que o container pode diretamente influenciar uma propriedade global do host.

Impacto:

- adulteração da identidade do host
- confundir logs, monitoring, ou automação que confiam no hostname
- geralmente não é um full escape por si só, a menos que combinado com outras fraquezas

Em ambientes no estilo Docker, um padrão útil de detecção no lado do host é:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Containers exibindo `UTSMode=host` estão compartilhando o namespace UTS do host e devem ser revisados com mais cuidado se também tiverem capacidades que lhes permitam chamar `sethostname()` ou `setdomainname()`.

## Verificações

Estes comandos são suficientes para ver se a carga de trabalho tem sua própria visão de hostname ou está compartilhando o namespace UTS do host.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
- A correspondência de identificadores de namespace com um processo do host pode indicar compartilhamento do UTS com o host.
- Se alterar o hostname afetar mais do que o próprio container, a carga de trabalho tem mais influência sobre a identidade do host do que deveria.
- Isso normalmente é um achado de prioridade mais baixa do que problemas em PID, mount ou user namespace, mas ainda assim confirma quão isolado o processo realmente está.

Na maioria dos ambientes, o UTS namespace deve ser visto principalmente como uma camada de isolamento de suporte. Raramente é a primeira coisa que você persegue em um breakout, mas ainda faz parte da consistência e segurança geral da visão do container.
{{#include ../../../../../banners/hacktricks-training.md}}
