# Espaço de nomes IPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Visão geral

O namespace IPC isola **System V IPC objects** e **POSIX message queues**. Isso inclui segmentos de memória compartilhada, semáforos e filas de mensagens que, de outra forma, seriam visíveis entre processos não relacionados no host. Em termos práticos, isso impede que um container se conecte casualmente a objetos IPC pertencentes a outras cargas de trabalho ou ao host.

Em comparação com mount, PID, or user namespaces, o namespace IPC é discutido com menos frequência, mas isso não deve ser confundido com irrelevância. Memória compartilhada e mecanismos IPC relacionados podem conter estados altamente úteis. Se o namespace IPC do host estiver exposto, a carga de trabalho pode ganhar visibilidade sobre objetos de coordenação entre processos ou dados que nunca deveriam atravessar a fronteira do container.

## Operação

Quando o runtime cria um novo namespace IPC, o processo obtém seu próprio conjunto isolado de identificadores IPC. Isso significa que comandos como `ipcs` mostram apenas os objetos disponíveis nesse namespace. Se o container, em vez disso, entrar no namespace IPC do host, esses objetos passam a fazer parte de uma visão global compartilhada.

Isso é especialmente relevante em ambientes onde aplicações ou serviços usam memória compartilhada intensamente. Mesmo quando o container não consegue escapar diretamente apenas através de IPC, o namespace pode leak informações ou permitir interferência entre processos que ajuda materialmente um ataque posterior.

## Laboratório

Você pode criar um namespace IPC privado com:
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

Docker e Podman isolam o IPC por padrão. Kubernetes normalmente dá ao Pod seu próprio IPC namespace, compartilhado entre containers no mesmo Pod, mas não com o host por padrão. O compartilhamento de IPC com o host é possível, mas deve ser tratado como uma redução significativa do isolamento em vez de uma opção menor de runtime.

## Misconfigurações

O erro óbvio é `--ipc=host` ou `hostIPC: true`. Isso pode ser feito por compatibilidade com software legado ou por conveniência, mas altera substancialmente o modelo de confiança. Outro problema recorrente é simplesmente negligenciar o IPC porque parece menos dramático do que host PID ou host networking. Na realidade, se a carga de trabalho lida com navegadores, bancos de dados, cargas de trabalho científicas ou outro software que faz uso intensivo de memória compartilhada, a superfície de IPC pode ser muito relevante.

## Abuso

Quando o IPC do host é compartilhado, um atacante pode inspecionar ou interferir em objetos de memória compartilhada, obter novas informações sobre o comportamento do host ou de cargas de trabalho vizinhas, ou combinar as informações obtidas ali com visibilidade de processos e capacidades do tipo ptrace. O compartilhamento de IPC frequentemente é uma fraqueza de suporte em vez do caminho completo de breakout, mas fraquezas de suporte importam porque encurtam e estabilizam cadeias de ataque reais.

O primeiro passo útil é enumerar quais objetos IPC estão visíveis:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Se o namespace IPC do host estiver compartilhado, grandes segmentos de memória compartilhada ou proprietários de objetos interessantes podem revelar o comportamento da aplicação imediatamente:
```bash
ipcs -m -p
ipcs -q -p
```
Em alguns ambientes, o próprio conteúdo de `/dev/shm` pode leak nomes de arquivos, artefatos ou tokens que valem a pena verificar:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
O compartilhamento de IPC raramente concede imediatamente host root por si só, mas pode expor dados e canais de coordenação que tornam ataques a processos posteriores muito mais fáceis.

### Exemplo Completo: `/dev/shm` Recuperação de Segredos

O caso de abuso completo mais realista é o roubo de dados, em vez da fuga direta. Se host IPC ou um amplo layout de shared-memory estiverem expostos, artefatos sensíveis às vezes podem ser recuperados diretamente:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Impacto:

- extração de segredos ou material de sessão deixado na memória compartilhada
- visão sobre as aplicações atualmente ativas no host
- melhor direcionamento para ataques posteriores PID-namespace ou baseados em ptrace

O compartilhamento de IPC é, portanto, mais bem entendido como um **amplificador de ataque** do que como uma primitiva de escape do host isolada.

## Checks

Estes comandos destinam-se a responder se a carga de trabalho possui uma visão privada de IPC, se objetos significativos de memória compartilhada ou mensagens são visíveis, e se `/dev/shm` por si só expõe artefatos úteis.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
- Se `ipcs -a` revelar objetos pertencentes a usuários ou serviços inesperados, o namespace pode não estar tão isolado quanto o esperado.
- Segmentos grandes ou incomuns de shared memory geralmente merecem investigação.
- Um mount amplo em `/dev/shm` não é automaticamente um bug, mas em alguns ambientes ele leaks nomes de arquivos, artefatos e segredos transitórios.

IPC raramente recebe tanta atenção quanto os tipos de namespace maiores, mas em ambientes que o utilizam intensamente, compartilhá-lo com o host é, de fato, uma decisão de segurança.
{{#include ../../../../../banners/hacktricks-training.md}}
