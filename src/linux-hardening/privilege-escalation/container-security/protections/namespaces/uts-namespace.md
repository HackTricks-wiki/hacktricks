# Namespace UTS

{{#include ../../../../../banners/hacktricks-training.md}}

## Visão geral

O namespace UTS isola o **nome do host** e o **nome de domínio NIS** visíveis pelo processo. À primeira vista isso pode parecer trivial em comparação com mount, PID ou user namespaces, mas faz parte do que faz um container parecer ser seu próprio host. Dentro do namespace, a carga de trabalho pode ver e às vezes alterar um nome de host que é local a esse namespace em vez de global à máquina.

Por si só, isso geralmente não é o ponto central de uma história de breakout. No entanto, uma vez que o UTS namespace do host seja compartilhado, um processo com privilégios suficientes pode influenciar configurações relacionadas à identidade do host, o que pode importar operacionalmente e, ocasionalmente, em termos de segurança.

## Laboratório

Você pode criar um namespace UTS com:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
A alteração do hostname permanece local para esse namespace e não altera o hostname global do host. Isto é uma demonstração simples, mas eficaz, da propriedade de isolamento.

## Uso em tempo de execução

Containers normais obtêm um namespace UTS isolado. Docker e Podman podem juntar-se ao namespace UTS do host através de `--uts=host`, e padrões semelhantes de compartilhamento com o host podem aparecer em outros runtimes e sistemas de orquestração. Na maioria das vezes, no entanto, o isolamento UTS privado faz parte da configuração normal do container e requer pouca atenção do operador.

## Impacto na Segurança

Embora o namespace UTS geralmente não seja o mais perigoso de compartilhar, ele ainda contribui para a integridade da fronteira do container. Se o namespace UTS do host estiver exposto e o processo tiver os privilégios necessários, ele pode ser capaz de alterar informações relacionadas ao hostname do host. Isso pode afetar monitoramento, registros, suposições operacionais ou scripts que tomam decisões de confiança com base em dados de identidade do host.

## Abuso

Se o namespace UTS do host estiver compartilhado, a questão prática é se o processo pode modificar as configurações de identidade do host em vez de apenas lê-las:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
Se o container também tiver o privilégio necessário, verifique se o hostname pode ser alterado:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
Isso é principalmente um problema de integridade e impacto operacional, em vez de um full escape, mas ainda mostra que o container pode influenciar diretamente uma propriedade global do host.

Impacto:

- manipulação da identidade do host
- confusão em logs, monitoramento ou automação que confiam no hostname
- normalmente não é um full escape por si só, a menos que combinado com outras fraquezas

Em ambientes estilo Docker, um padrão útil de detecção do lado do host é:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
Containers mostrando `UTSMode=host` estão compartilhando o namespace UTS do host e devem ser revisados com mais cuidado se também carregarem capabilities que lhes permitam chamar `sethostname()` ou `setdomainname()`.

## Verificações

Estes comandos são suficientes para verificar se a workload tem sua própria visão de hostname ou está compartilhando o namespace UTS do host.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
O que é interessante aqui:

- Correspondência de identificadores de namespace com um processo do host pode indicar compartilhamento do UTS do host.
- Se mudar o hostname afeta mais do que o próprio container, o workload tem mais influência sobre a identidade do host do que deveria.
- Isto geralmente é um achado de prioridade mais baixa do que problemas com PID, mount ou user namespace, mas ainda confirma o quão isolado o processo realmente está.

Na maioria dos ambientes, o UTS namespace deve ser visto como uma camada de isolamento auxiliar. Raramente é a primeira coisa que você persegue em um breakout, mas ainda faz parte da consistência e segurança gerais da visão do container.
