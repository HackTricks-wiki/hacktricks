# Namespace IPC

{{#include ../../../../../banners/hacktricks-training.md}}

## Visão geral

O namespace IPC isola **objetos IPC do System V** e **filas de mensagens POSIX**. Isso inclui segmentos de memória compartilhada, semáforos e filas de mensagens que, de outra forma, seriam visíveis para processos não relacionados no host. Em termos práticos, isso impede que um container se conecte casualmente a objetos IPC pertencentes a outras workloads ou ao host.

Em comparação com os namespaces de mount, PID ou user, o namespace IPC é discutido com menos frequência, mas isso não deve ser confundido com irrelevância. A memória compartilhada e os mecanismos IPC relacionados podem conter informações de estado muito úteis. Se o namespace IPC do host estiver exposto, a workload poderá obter visibilidade sobre objetos ou dados de coordenação entre processos que nunca deveriam ultrapassar os limites do container.

## Operação

Quando o runtime cria um novo namespace IPC, o processo obtém seu próprio conjunto isolado de identificadores IPC. Isso significa que comandos como `ipcs` mostram apenas os objetos disponíveis nesse namespace. Se, em vez disso, o container ingressar no namespace IPC do host, esses objetos passarão a fazer parte de uma visão global compartilhada.

Isso é especialmente relevante em ambientes nos quais aplicativos ou serviços usam intensivamente a memória compartilhada. Mesmo quando o container não consegue escapar diretamente apenas por meio de IPC, o namespace pode causar um leak de informações ou permitir interferência entre processos, ajudando significativamente em um ataque posterior.

## Lab

Você pode criar um namespace IPC privado com:
```bash
sudo unshare --ipc --fork bash
ipcs
```
E compare o comportamento em runtime com:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Uso em Runtime

Docker e Podman isolam o IPC por padrão. O Kubernetes normalmente fornece ao Pod seu próprio namespace de IPC, compartilhado entre os containers no mesmo Pod, mas não por padrão com o host. O compartilhamento do IPC do host é possível, mas deve ser tratado como uma redução significativa no isolamento, e não como uma opção secundária do runtime.

## Configurações incorretas

O erro óbvio é `--ipc=host` ou `hostIPC: true`. Isso pode ser feito por compatibilidade com software legado ou por conveniência, mas altera substancialmente o modelo de confiança. Outro problema recorrente é simplesmente ignorar o IPC porque ele parece menos dramático que o PID do host ou a rede do host. Na realidade, se o workload lida com browsers, bancos de dados, workloads científicos ou outro software que faz uso intenso de memória compartilhada, a superfície de IPC pode ser muito relevante.

## Abuso

Quando o IPC do host é compartilhado, um attacker pode inspecionar ou interferir em objetos de memória compartilhada, obter novos insights sobre o comportamento do host ou de workloads vizinhos, ou combinar as informações obtidas com visibilidade de processos e capacidades no estilo do ptrace. O compartilhamento de IPC frequentemente é uma fraqueza de suporte, e não o caminho completo de escape, mas fraquezas de suporte são importantes porque encurtam e estabilizam cadeias de ataque reais.

O primeiro passo útil é enumerar quais objetos de IPC estão visíveis:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Se o IPC namespace do host for compartilhado, grandes segmentos de memória compartilhada ou proprietários de objetos interessantes podem revelar imediatamente o comportamento da aplicação:
```bash
ipcs -m -p
ipcs -q -p
```
Em alguns ambientes, o próprio conteúdo de `/dev/shm` pode leakar nomes de arquivos, artefatos ou tokens que vale a pena verificar:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
O compartilhamento de IPC raramente concede root instantâneo no host por si só, mas pode expor dados e canais de coordenação que tornam ataques posteriores a processos muito mais fáceis.

### Exemplo completo: recuperação de segredos em `/dev/shm`

O caso completo de abuso mais realista é o roubo de dados, em vez de um escape direto. Se o IPC do host ou um layout amplo de memória compartilhada estiver exposto, artefatos sensíveis às vezes podem ser recuperados diretamente:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Impacto:

- extração de secrets ou material de sessão deixado na memória compartilhada
- informações sobre as aplicações atualmente ativas no host
- melhor direcionamento para ataques posteriores baseados em PID namespace ou ptrace

O compartilhamento de IPC é, portanto, mais bem compreendido como um **amplificador de ataque** do que como uma primitiva autônoma de escape do host.

## Verificações

Estes comandos têm como objetivo determinar se o workload possui uma visão privada de IPC, se objetos relevantes de memória compartilhada ou mensagens estão visíveis e se o próprio `/dev/shm` expõe artefatos úteis.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
O que é interessante aqui:

- Se `ipcs -a` revelar objetos pertencentes a usuários ou serviços inesperados, o namespace pode não estar tão isolado quanto o esperado.
- Segmentos de memória compartilhada grandes ou incomuns geralmente merecem uma investigação mais aprofundada.
- Um mount amplo de `/dev/shm` não é automaticamente um bug, mas, em alguns ambientes, ele leaks nomes de arquivos, artefatos e secrets temporários.

O IPC raramente recebe tanta atenção quanto os tipos de namespace mais importantes, mas, em ambientes que o utilizam intensivamente, compartilhá-lo com o host é, sem dúvida, uma decisão de segurança.
{{#include ../../../../../banners/hacktricks-training.md}}
