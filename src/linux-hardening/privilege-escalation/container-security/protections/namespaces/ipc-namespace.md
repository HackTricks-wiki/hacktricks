# Espaço de nomes IPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Visão geral

O Espaço de nomes IPC isola **System V IPC objects** e **POSIX message queues**. Isso inclui segmentos de memória compartilhada, semáforos e filas de mensagens que, de outra forma, seriam visíveis entre processos não relacionados no host. Na prática, isso impede que um container se anexe casualmente a objetos IPC pertencentes a outras cargas de trabalho ou ao host.

Comparado com mount, PID, ou user namespaces, o Espaço de nomes IPC é discutido com menos frequência, mas isso não deve ser confundido com irrelevância. A memória compartilhada e os mecanismos IPC relacionados podem conter estado muito útil. Se o espaço de nomes IPC do host for exposto, a workload pode ganhar visibilidade sobre objetos de coordenação entre processos ou dados que nunca foram destinados a atravessar a fronteira do container.

## Operação

Quando o runtime cria um novo espaço de nomes IPC, o processo obtém seu próprio conjunto isolado de identificadores IPC. Isso significa que comandos como `ipcs` mostram apenas os objetos disponíveis nesse namespace. Se o container, em vez disso, entrar no espaço de nomes IPC do host, esses objetos passam a fazer parte de uma visão global compartilhada.

Isso importa especialmente em ambientes onde aplicações ou serviços usam memória compartilhada intensamente. Mesmo quando o container não pode escapar diretamente apenas através do IPC, o namespace pode leak informações ou permitir interferência entre processos que ajuda materialmente um ataque posterior.

## Laboratório

Você pode criar um espaço de nomes IPC privado com:
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

Docker e Podman isolam IPC por padrão. O Kubernetes tipicamente dá ao Pod seu próprio namespace IPC, compartilhado pelos containers no mesmo Pod, mas não por padrão com o host. Compartilhar o IPC do host é possível, mas deve ser tratado como uma redução significativa do isolamento em vez de uma opção de tempo de execução menor.

## Misconfigurações

O erro óbvio é `--ipc=host` ou `hostIPC: true`. Isso pode ser feito por compatibilidade com software legado ou por conveniência, mas altera substancialmente o modelo de confiança. Outro problema recorrente é simplesmente negligenciar o IPC porque parece menos dramático que host PID ou host networking. Na realidade, se a carga de trabalho lida com browsers, databases, scientific workloads, ou outro software que faça uso intensivo de memória compartilhada, a superfície de IPC pode ser muito relevante.

## Abuso

Quando o IPC do host é compartilhado, um atacante pode inspecionar ou interferir em objetos de memória compartilhada, obter novos insights sobre o comportamento do host ou de cargas de trabalho vizinhas, ou combinar as informações aprendidas ali com visibilidade de processos e capacidades do tipo ptrace. O compartilhamento de IPC costuma ser uma fraqueza de suporte em vez do caminho completo de breakout, mas fraquezas de suporte importam porque encurtam e estabilizam cadeias de ataque reais.

O primeiro passo útil é enumerar quais objetos IPC são visíveis:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Se o host IPC namespace for compartilhado, grandes segmentos de memória compartilhada ou proprietários de objetos interessantes podem revelar o comportamento da aplicação imediatamente:
```bash
ipcs -m -p
ipcs -q -p
```
Em alguns ambientes, o próprio conteúdo de `/dev/shm` pode leak nomes de arquivos, artefatos ou tokens que valem a pena verificar:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
O compartilhamento de IPC raramente concede root do host instantaneamente por si só, mas pode expor dados e canais de coordenação que tornam ataques a processos posteriores muito mais fáceis.

### Exemplo completo: Recuperação de segredos em `/dev/shm`

O caso de abuso completo mais realista é o roubo de dados em vez do escape direto. Se o IPC do host ou um amplo layout de memória compartilhada estiver exposto, artefatos sensíveis às vezes podem ser recuperados diretamente:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Impacto:

- extração de segredos ou material de sessão deixados em memória compartilhada
- visão das aplicações atualmente ativas no host
- melhor direcionamento para ataques posteriores baseados em PID-namespace ou ptrace

O compartilhamento de IPC é, portanto, melhor entendido como um **amplificador de ataque** do que como uma primitiva de escape do host independente.

## Verificações

Esses comandos destinam-se a responder se a carga de trabalho tem uma visão de IPC privada, se objetos significativos de memória compartilhada ou de mensagem são visíveis, e se o próprio `/dev/shm` expõe artefatos úteis.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
What is interesting here:

- Se `ipcs -a` revelar objetos pertencentes a usuários ou serviços inesperados, o namespace pode não estar tão isolado quanto o esperado.
- Segmentos de memória compartilhada grandes ou incomuns costumam valer a investigação.
- Um mount amplo em `/dev/shm` não é automaticamente um bug, mas em alguns ambientes ele leaks nomes de arquivo, artefatos e segredos transitórios.

IPC raramente recebe tanta atenção quanto os tipos de namespace maiores, mas em ambientes que o usam intensamente, compartilhá-lo com o host é, de fato, uma decisão de segurança.
