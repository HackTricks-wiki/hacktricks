# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Visão geral

O IPC namespace isola **System V IPC objects** e **POSIX message queues**. Isso inclui shared memory segments, semaphores, e message queues que, de outra forma, seriam visíveis entre processos não relacionados no host. Em termos práticos, isso impede que um container se anexe casualmente a objetos IPC pertencentes a outras workloads ou ao host.

Comparado com mount, PID ou user namespaces, o IPC namespace é discutido com menos frequência, mas isso não deve ser confundido com irrelevância. Shared memory e mecanismos IPC relacionados podem conter estado altamente útil. Se o host IPC namespace estiver exposto, a workload pode ganhar visibilidade sobre objetos de coordenação entre processos ou dados que nunca deveriam atravessar a fronteira do container.

## Funcionamento

Quando o runtime cria um IPC namespace novo, o processo recebe seu próprio conjunto isolado de identificadores IPC. Isso significa que comandos como `ipcs` mostram apenas os objetos disponíveis naquele namespace. Se o container, em vez disso, ingressar no host IPC namespace, esses objetos passam a fazer parte de uma visão global compartilhada.

Isso importa especialmente em ambientes onde aplicações ou serviços usam shared memory intensamente. Mesmo quando o container não pode escapar diretamente através de IPC sozinho, o namespace pode leak informações ou permitir interferência entre processos que ajuda materialmente um ataque posterior.

## Laboratório

Você pode criar um IPC namespace privado com:
```bash
sudo unshare --ipc --fork bash
ipcs
```
E compare o comportamento em tempo de execução com:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Uso em tempo de execução

Docker e Podman isolam IPC por padrão. O Kubernetes normalmente fornece ao Pod seu próprio namespace IPC, compartilhado entre contêineres no mesmo Pod, mas não com o host por padrão. O compartilhamento de IPC com o host é possível, mas deve ser tratado como uma redução significativa do isolamento em vez de uma opção de tempo de execução menor.

## Configurações incorretas

O erro óbvio é `--ipc=host` ou `hostIPC: true`. Isso pode ser feito por compatibilidade com software legado ou por conveniência, mas altera substancialmente o modelo de confiança. Outro problema recorrente é simplesmente ignorar o IPC porque parece menos dramático do que host PID ou host networking. Na realidade, se a carga de trabalho lida com navegadores, bancos de dados, cargas de trabalho científicas ou outro software que faz uso intensivo de memória compartilhada, a superfície de IPC pode ser muito relevante.

## Abuso

Quando o IPC do host é compartilhado, um atacante pode inspecionar ou interferir com objetos de memória compartilhada, obter novos insights sobre o comportamento do host ou de cargas de trabalho vizinhas, ou combinar as informações aprendidas ali com visibilidade de processos e capacidades do tipo ptrace. O compartilhamento de IPC costuma ser uma fraqueza de suporte em vez do caminho completo de breakout, mas fraquezas de suporte importam porque encurtam e estabilizam cadeias de ataque reais.

O primeiro passo útil é enumerar quais objetos IPC estão visíveis:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Se o namespace IPC do host for compartilhado, grandes segmentos de memória compartilhada ou proprietários de objetos interessantes podem revelar imediatamente o comportamento da aplicação:
```bash
ipcs -m -p
ipcs -q -p
```
Em alguns ambientes, o conteúdo de `/dev/shm` em si pode leak nomes de arquivos, artefatos ou tokens que valem a pena verificar:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
O compartilhamento de IPC raramente concede host root instantaneamente por si só, mas pode expor canais de dados e de coordenação que tornam ataques posteriores a processos muito mais fáceis.

### Exemplo completo: `/dev/shm` Recuperação de Segredos

O caso de abuso completo mais realista é o roubo de dados, em vez da fuga direta. Se o host IPC ou uma ampla disposição de memória compartilhada estiver exposta, artefatos sensíveis às vezes podem ser recuperados diretamente:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Impacto:

- extração de segredos ou material de sessão deixado na memória compartilhada
- visibilidade das aplicações atualmente ativas no host
- melhor direcionamento para ataques posteriores baseados em PID-namespace ou em ptrace

O compartilhamento de IPC é, portanto, melhor compreendido como um **amplificador de ataque** do que como uma primitiva isolada de escape do host.

## Verificações

Esses comandos têm como objetivo responder se a carga de trabalho possui uma visão IPC privada, se objetos significativos de memória compartilhada ou de mensagem estão visíveis, e se o próprio `/dev/shm` expõe artefatos úteis.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
- If `ipcs -a` reveals objects owned by unexpected users or services, the namespace may not be as isolated as expected.
- Segmentos de memória compartilhada grandes ou incomuns costumam valer uma investigação.
- Um mount amplo em `/dev/shm` não é automaticamente um bug, mas em alguns ambientes ele leaks nomes de arquivos, artefatos e segredos transitórios.

IPC raramente recebe tanta atenção quanto os tipos de namespace maiores, mas em ambientes que o usam muito, compartilhá-lo com o host é, de fato, uma decisão de segurança.
{{#include ../../../../../banners/hacktricks-training.md}}
